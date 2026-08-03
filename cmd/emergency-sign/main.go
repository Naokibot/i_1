package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	runtimepkg "github.com/Naokibot/i_1/internal/runtime"
)

func main() {
	privateKeyPath := flag.String("private-key", "", "base64 Ed25519 private key file")
	publicKeyPath := flag.String("public-key", "", "output public key file for keygen")
	input := flag.String("input", "", "input directive JSON")
	output := flag.String("output", "", "output directive JSON")
	approver := flag.String("approver", "", "approver name for approve")
	flag.Parse()
	if flag.NArg() != 1 {
		usage()
	}
	var err error
	switch flag.Arg(0) {
	case "keygen":
		err = keygen(*privateKeyPath, *publicKeyPath)
	case "sign-root":
		err = transform(*input, *output, func(d runtimepkg.EmergencyDirective) (runtimepkg.EmergencyDirective, error) {
			key, err := readPrivateKey(*privateKeyPath)
			if err != nil {
				return runtimepkg.EmergencyDirective{}, err
			}
			return runtimepkg.SignEmergencyDirective(key, d)
		})
	case "approve":
		if strings.TrimSpace(*approver) == "" {
			err = errors.New("approve requires -approver")
			break
		}
		err = transform(*input, *output, func(d runtimepkg.EmergencyDirective) (runtimepkg.EmergencyDirective, error) {
			key, err := readPrivateKey(*privateKeyPath)
			if err != nil {
				return runtimepkg.EmergencyDirective{}, err
			}
			return runtimepkg.SignEmergencyApproval(key, *approver, d)
		})
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func keygen(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" {
		return errors.New("keygen requires -private-key and -public-key")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o644)
}

func transform(input, output string, operation func(runtimepkg.EmergencyDirective) (runtimepkg.EmergencyDirective, error)) error {
	if input == "" || output == "" {
		return errors.New("operation requires -input and -output")
	}
	file, err := os.Open(input)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(file, 2<<20))
	decoder.DisallowUnknownFields()
	var directive runtimepkg.EmergencyDirective
	decodeErr := decoder.Decode(&directive)
	closeErr := file.Close()
	if decodeErr != nil {
		return decodeErr
	}
	if closeErr != nil {
		return closeErr
	}
	directive, err = operation(directive)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(directive, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(output, append(data, '\n'), 0o600)
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("private key path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid base64 Ed25519 private key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: emergency-sign [flags] keygen|sign-root|approve")
	os.Exit(2)
}
