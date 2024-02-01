// Copyright 2018 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"crypto/rand"
	"github.com/miekg/pkcs11"
	"testing"

	"github.com/stretchr/testify/require"
)

func initBlock(character byte, length int) []byte {
	dst := make([]byte, length)
	for i := 0; i < length; i++{
		dst[i] = character
	}
	return dst
}

func TestBlock(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	// get or generate a new temporary key for encryption / decryption operations in the pkcs11 store
	var key *SecretKey
	if ctx.cfg.Tpm {
		//key, err = ctx.FindKey(nil, []byte(ctx.cfg.SecretKeyLabel))
		key, err = ctx.FindKey(nil, []byte("aes0"))
	} else {
		keyType := pkcs11.CKK_AES
		keySize := 256
		id := make([]byte, 16)
		rand.Read(id)
		key, err = ctx.GenerateSecretKeyWithLabel(id, []byte("testblock"), keySize, Ciphers[keyType])
		defer key.Delete()
	}
	if err != nil {
		panic(err)
	}

	iv, _ := makeIV(key.Cipher)

	t.Run("AES256 CBC", func(t *testing.T) { testCBC(t, key, iv) })
	t.Run("AES256 CBC", func(t *testing.T) { testCBCPadding(t, key, iv) })
}

func testCBC(t *testing.T, key *SecretKey, iv []byte){
	short := []byte("ping")
	block := []byte("helloblockworld!")
	long := []byte("thisisbiggerthanablock")

	bm, err := key.NewBlockManagerCBC(iv)
	require.NoError(t, err)

	encShort := initBlock('s', bm.BlockSize()-1)
	encBlock := initBlock('b', bm.BlockSize())
	encLong := initBlock('l', bm.BlockSize()+1)
	compareShort := make([]byte, bm.BlockSize()-1)
	compareBlock := make([]byte, bm.BlockSize())
	compareLong := make([]byte, bm.BlockSize()+1)
	copy(compareShort, encShort)
	copy(compareBlock, encBlock)
	copy(compareLong, encLong)

	// encryption fails when buffers are equal without padding
	// should fail
	// source too small
	bm.Encrypt(encBlock, short)
	require.Equal(t, encBlock, compareBlock, "returns the same (not encrypted) since the source buffer is too small")
	// source too long
	bm.Encrypt(encBlock, long)
	require.Equal(t, encBlock, compareBlock, "returns the same (not encrypted) since the source buffer is too long")
	// destination too small
	bm.Encrypt(encShort, block)
	require.Equal(t, encShort, compareShort, "returns the same (not encrypted) since the destination buffer is too short")
	// should succeed
	// destination matches block size
	bm.Encrypt(encBlock, block)
	require.NotEqual(t, encBlock, compareBlock, "returns encrypted array since the source buffer is exactly equal to one block size")
	// destination buffer long enough
	bm.Encrypt(encLong, block)
	require.NotEqual(t, encLong, compareLong, "returns encrypted array since the destination buffer is long enough to handle the cipher text")

	// decryption
	// should fail
	// source buffer too small
	bm.Decrypt(compareBlock, short)
	require.Equal(t, compareBlock, initBlock('b', bm.BlockSize()), "returns the same sinceThe source buffer is too small")
	// source buffer too long
	bm.Decrypt(compareBlock, long)
	require.Equal(t, compareBlock, initBlock('b', bm.BlockSize()), "returns the same since the source buffer is too long")
	// destination buffer too small
	bm.Decrypt(compareShort, encBlock)
	require.Equal(t, compareShort, initBlock('s', bm.BlockSize()-1), "returns the same (still encrypted) since the destination buffer is too small")
	// should succeed
	// destination matches block size
	bm.Decrypt(compareBlock, encBlock)
	require.Equal(t, compareBlock, block, "returns the decrypted blocks")
	// destination buffer long enough
	bm.Decrypt(compareLong, encBlock)
	require.NotEqual(t, compareLong, block, "returns the decrypted blocks in a longer buffer")
	newCompareBlock := make([]byte, bm.BlockSize())
	copy(newCompareBlock, compareLong)
	require.Equal(t, newCompareBlock, block, "returns the decrypted blocks")
}

func testCBCPadding(t *testing.T, key *SecretKey, iv []byte){
	short := []byte("ping")
	block := []byte("helloblockworld!")
	long := []byte("thisisbiggerthanablock")

	bm, err := key.NewBlockManagerCBCPadding(iv)
	require.NoError(t, err)

	encTooShort := initBlock('t', bm.BlockSize()-1)
	encShort := initBlock('s', bm.BlockSize())
	encBlock := initBlock('b', 2*bm.BlockSize())
	encLong := initBlock('l', 2*bm.BlockSize())
	compareTooShort := make([]byte, bm.BlockSize()-1)
	compareShort := make([]byte, bm.BlockSize())
	compareBlock := make([]byte, 2*bm.BlockSize())
	compareLong := make([]byte, 2*bm.BlockSize())
	copy(compareTooShort, encTooShort)
	copy(compareShort, encShort)
	copy(compareBlock, encBlock)
	copy(compareLong, encLong)

	// should fail
	// destination too small
	bm.Encrypt(encTooShort, block)
	require.Equal(t, encTooShort, compareTooShort, "returns the same (not encrypted) since the destination buffer is too short")
	// should succeed
	// destination matches block size
	// BEWARE ! With padding, encrypting a block shall be at destination of a 2 blocks buffer sized
	bm.Encrypt(encBlock, block)
	require.NotEqual(t, encBlock, compareLong, "returns encrypted array since the source buffer is exactly equal to one block size")
	// source is smaller than block size
	bm.Encrypt(encShort, short)
	require.NotEqual(t, encShort, compareShort, "returns encrypted array since the source buffer is exactly equal to one block size")
	// source is larger than block size
	bm.Encrypt(encLong, long)
	require.NotEqual(t, encLong, compareLong, "returns encrypted array since the source buffer is exactly equal to one block size")

	// decryption
	// should fail
	// destination buffer too small
	bm.Decrypt(compareTooShort, encBlock)
	require.Equal(t, compareTooShort, initBlock('t', bm.BlockSize()-1), "returns the same (still encrypted) since the destination buffer is too small")
	// should succeed
	// destination matches block size
	bm.Decrypt(compareBlock, encBlock)
	require.NotEqual(t, compareBlock, block, "return the decrypted plaintext in a longer buffer")
	newCompareBlock := make([]byte, len(block))
	copy(newCompareBlock, compareBlock)
	require.Equal(t, newCompareBlock, block, "returns the decrypted block")
	// original plaintext was shorter than block size
	bm.Decrypt(compareShort, encShort)
	require.NotEqual(t, compareShort, short, "returns the decrypted small plaintext in a longer buffer")
	newCompareShort := make([]byte, len(short))
	copy(newCompareShort, compareShort)
	require.Equal(t, newCompareShort, short, "returns the decrypted short block")
	// original plaintext was longer than block size
	bm.Decrypt(compareLong, encLong)
	require.NotEqual(t, compareLong, long, "returns the decrypted small plaintext in a longer buffer")
	newCompareLong := make([]byte, len(long))
	copy(newCompareLong, compareLong)
	require.Equal(t, newCompareLong, long, "returns the decrypted long blocks")
}



