package scanner

import (
	"bufio"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurePathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.go"), []byte("MD5"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := securePath(root, link); err == nil {
		t.Fatal("securePath accepted a symlink escaping the allowed root")
	}
}

func TestReadSSHIdentificationRejectsOversizedLine(t *testing.T) {
	input := strings.Repeat("A", maxSSHIdentificationBytes+1) + "\nSSH-2.0-test\r\n"
	_, err := readSSHIdentification(bufio.NewReader(strings.NewReader(input)))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readSSHIdentification error=%v, want size rejection", err)
	}
}

func TestReadSSHPacketRejectsLargeAllocation(t *testing.T) {
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[:4], uint32(maxSSHPacketBytes+1))
	header[4] = 8
	_, err := readSSHPacket(bufio.NewReader(strings.NewReader(string(header))))
	if err == nil || !strings.Contains(err.Error(), "invalid SSH packet length") {
		t.Fatalf("readSSHPacket error=%v, want packet length rejection", err)
	}
}
