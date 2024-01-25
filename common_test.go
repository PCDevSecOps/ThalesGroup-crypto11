package crypto11

import (
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"
)



func skipIfMechUnsupported(t *testing.T, ctx *Context, wantMech uint) {
	mechs, err := ctx.ctx.GetMechanismList(ctx.slot)
	require.NoError(t, err)

	for _, mech := range mechs {
		if mech.Mechanism == wantMech {
			return
		}
	}
	t.Skipf("mechanism 0x%x not supported", wantMech)
}

// randomBytes returns 32 random bytes.
func randomBytes() []byte {
	result := make([]byte, 32)
	rand.Read(result)
	return result
}

func TestULongMasking(t *testing.T) {
	ulongData := uint(0x33221100ddccbbaa)
	ulongSlice := ulongToBytes(ulongData)

	// Build an slice that is longer than the size of a ulong
	extraLongSlice := append(ulongSlice, ulongSlice...)

	tests := []struct {
		slice    []uint8
		expected uint
	}{
		{ulongSlice[0:0], 0},
		{ulongSlice[0:1], 0xaa},
		{ulongSlice[0:2], 0xbbaa},
		{ulongSlice[0:3], 0xccbbaa},
		{ulongSlice[0:4], 0xddccbbaa},
		{ulongSlice[0:5], 0x00ddccbbaa},
		{ulongSlice[0:6], 0x1100ddccbbaa},
		{ulongSlice[0:7], 0x221100ddccbbaa},
		{ulongSlice[0:8], 0x33221100ddccbbaa},
		{extraLongSlice, 0x33221100ddccbbaa},
	}

	for _, test := range tests {
		got := bytesToUlong(test.slice)
		if test.expected != got {
			t.Errorf("conversion failed: 0x%X != 0x%X", test.expected, got)
		}
	}
}

func makeIV(cipher *SymmetricCipher) ([]byte, error) {
	iv := make([]byte, cipher.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}

