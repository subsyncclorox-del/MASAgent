package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestChainIntact(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, "ENG-1")
	if err := l.Decision("spider", "example.com:443", true, "in scope"); err != nil {
		t.Fatal(err)
	}
	if err := l.Decision("spider", "evil.com:443", false, "out of scope"); err != nil {
		t.Fatal(err)
	}
	n, broken, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || broken != 0 {
		t.Fatalf("expected 2 intact records, got n=%d broken=%d", n, broken)
	}
}

func TestChainDetectsTampering(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, "ENG-1")
	_ = l.Decision("a", "t1", true, "r1")
	_ = l.Decision("a", "t2", false, "r2")
	// Tamper: flip an allowed decision in the raw text.
	tampered := strings.Replace(buf.String(), `"reason":"r1"`, `"reason":"HACKED"`, 1)
	_, broken, err := Verify(strings.NewReader(tampered))
	if err != nil {
		t.Fatal(err)
	}
	if broken == 0 {
		t.Fatal("expected tampering to be detected")
	}
}
