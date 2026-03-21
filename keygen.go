package main

import (
	"crypto/ecdh"
	"crypto/rand"
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
}

func main() {
	// Generate key pair X25519
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey()
	privBytes := priv.Bytes()
	pubBytes := pub.Bytes()

	// Generate ID 8 digit angka acak
	idBytes := make([]byte, 4)
	rand.Read(idBytes)
	id := fmt.Sprintf("%08d", int(idBytes[0])<<24|int(idBytes[1])<<16|int(idBytes[2])<<8|int(idBytes[3])%100000000)
	if len(id) > 8 {
		id = id[:8]
	}

	pubKeyStr := formatByteSlice(pubBytes)
	privKeyStr := formatByteSlice(privBytes)

	data := KeyData{
		ID:              id,
		PublicKeyBytes:  pubKeyStr,
		PrivateKeyBytes: privKeyStr,
	}

	// Proses template encryptor
	err = processTemplate("encryptor_template.go", "encryptor_gen.go", data)
	if err != nil {
		panic(err)
	}
	defer os.Remove("encryptor_gen.go")

	// Proses template decryptor
	err = processTemplate("decryptor_template.go", "decryptor_gen.go", data)
	if err != nil {
		panic(err)
	}
	defer os.Remove("decryptor_gen.go")

	// Build encryptor dengan nama e_ID.exe
	outEnc := fmt.Sprintf("e_%s.exe", id)
	cmd := exec.Command("go", "build", "-o", outEnc, "encryptor_gen.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
	fmt.Printf("Encryptor built: %s\n", outEnc)

	// Build decryptor dengan nama d_ID.exe
	outDec := fmt.Sprintf("d_%s.exe", id)
	cmd = exec.Command("go", "build", "-o", outDec, "decryptor_gen.go")
	if err := cmd.Run(); err != nil {
		panic(err)
	}
	fmt.Printf("Decryptor built: %s\n", outDec)

	// Simpan kunci ke file ID.txt
	keyFile := fmt.Sprintf("%s.txt", id)
	content := fmt.Sprintf("ID: %s\nPublic Key (bytes): %s\nPrivate Key (bytes): %s\n\nPublic Key (hex): %x\nPrivate Key (hex): %x\n",
		id, pubKeyStr, privKeyStr, pubBytes, privBytes)
	err = os.WriteFile(keyFile, []byte(content), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Keys saved to: %s\n", keyFile)
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