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
		key, err = ctx.FindKey(nil, []byte(ctx.cfg.SecretKeyLabel))
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

	t.Run("AES256 CBC PAD", func(t *testing.T) {
		testBlockCBCPadding(t, key) })
	//t.Run("AES256", func(t *testing.T) { test2(t) })
}

func testBlockCBCPadding(t *testing.T, key *SecretKey) {
	short := []byte("ping")
	block := []byte("helloblockworld!")
	large := []byte("thisisbiggerthanablock")
	iv, _ := makeIV(key.Cipher)
	mech := key.Cipher.CBCPKCSMech

	// encryption
	shortCipher, err := key.Encrypt(mech, iv, short)
	blockCipher, err := key.Encrypt(mech, iv, block)
	largeCipher, err := key.Encrypt(mech, iv, large)

	require.NoError(t, err)
	require.NotNil(t, shortCipher)
	require.NotNil(t, blockCipher)
	require.NotNil(t, largeCipher)
	require.NotEmpty(t, shortCipher)
	require.NotEmpty(t, blockCipher)
	require.NotEmpty(t, largeCipher)

	// decryption
	shortClear, err := key.Decrypt(mech, iv, shortCipher)
	blockClear, err := key.Decrypt(mech, iv, blockCipher)
	largeClear, err := key.Decrypt(mech, iv, largeCipher)

	require.NoError(t, err)
	require.NotNil(t, shortClear)
	require.NotNil(t, blockClear)
	require.NotNil(t, largeClear)

	require.Equal(t, short, shortClear)
	require.Equal(t, block, blockClear)
	require.Equal(t, large, largeClear)
}
