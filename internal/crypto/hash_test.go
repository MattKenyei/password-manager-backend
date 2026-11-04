package crypto

import (
	"bytes"
	"testing"
)

func TestHashAuthKey_Deterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	h1 := HashAuthKey(key)
	h2 := HashAuthKey(key)
	if !bytes.Equal(h1, h2) {
		t.Fatal("not deterministic")
	}
	if len(h1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(h1))
	}
}

func TestHashAuthKey_DifferentInputs(t *testing.T) {
	h1 := HashAuthKey([]byte("input-a"))
	h2 := HashAuthKey([]byte("input-b"))
	if bytes.Equal(h1, h2) {
		t.Fatal("different inputs gave same hash")
	}
}

func TestHashAuthKey_EmptyInput(t *testing.T) {
	h := HashAuthKey(nil)
	if len(h) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(h))
	}
	// SHA-256 of empty string is a well-known constant.
	emptyHash := HashAuthKey([]byte{})
	if !bytes.Equal(h, emptyHash) {
		t.Fatal("nil and empty slice must hash identically")
	}
}
