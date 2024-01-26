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

func TestBlock(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, ctx.Close())
	}()

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
	t.Run("AES256 CBC", func(t *testing.T) { testCBCPad(t, key, iv) })
}

func testCBC(t *testing.T, key *SecretKey, iv []byte){
	short := []byte("ping")
	block := []byte("helloblockworld!")
	large := []byte("thisisbiggerthanablock")

	// encryption
	// should fail
	shortCipher, err := key.EncryptCBC(iv, short)
	require.Error(t, err)
	require.Nil(t, shortCipher)
	// should fail
	largeCipher, err := key.EncryptCBC(iv, large)
	require.Error(t, err)
	require.Nil(t, largeCipher)
	// should succeed
	blockCipher, err := key.EncryptCBC(iv, block)
	require.NoError(t, err)
	require.Equal(t, key.Cipher.BlockSize, len(blockCipher))

	// decryption
	// should fail
	shortClear, err := key.DecryptCBC(iv, shortCipher)
	require.Error(t, err)
	require.Nil(t, shortClear)
	// should fail
	largeClear, err := key.DecryptCBC(iv, largeCipher)
	require.Error(t, err)
	require.Nil(t, largeClear)
	// should succeed
	blockClear, err := key.DecryptCBC(iv, blockCipher)
	require.NoError(t, err)
	require.Equal(t, block, blockClear)

}

func testCBCPad(t *testing.T, key *SecretKey, iv []byte){
	short := []byte("ping")
	block := []byte("helloblockworld!")
	large := []byte("thisisbiggerthanablock")

	// encryption
	// should fail
	shortCipher, err := key.EncryptCBCPadding(iv, short)
	require.NoError(t, err)
	require.Equal(t, key.Cipher.BlockSize, len(shortCipher))
	// should fail
	largeCipher, err := key.EncryptCBCPadding(iv, large)
	require.NoError(t, err)
	require.Equal(t, 2*key.Cipher.BlockSize, len(largeCipher))
	// should succeed
	blockCipher, err := key.EncryptCBCPadding(iv, block)
	require.NoError(t, err)
	require.Equal(t, 2*key.Cipher.BlockSize, len(blockCipher))

	// decryption
	// should fail
	shortClear, err := key.DecryptCBCPadding(iv, shortCipher)
	require.NoError(t, err)
	require.Equal(t, short, shortClear)
	// should fail
	largeClear, err := key.DecryptCBCPadding(iv, largeCipher)
	require.NoError(t, err)
	require.Equal(t, large, largeClear)
	// should succeed
	blockClear, err := key.DecryptCBCPadding(iv, blockCipher)
	require.NoError(t, err)
	require.Equal(t, block, blockClear)

}



