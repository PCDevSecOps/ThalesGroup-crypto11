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
	"crypto/cipher"
	"fmt"
	"log"

	"github.com/miekg/pkcs11"
)

// BlockManager
// Use its functions to encrypt/decrypt cleartext/ciphertext in one go.
// This approach is simple but lack of efficiency for bulk operations.
// For a more efficient approach, check BlockModeCloser instead.
type BlockManager interface {
	cipher.Block

	HasPadding() bool
}

type blockManager struct {
	// PKCS#11 session to use
	session *pkcs11Session

	// The PKCS#11 object key keyHandle to use
	keyHandle *pkcs11.ObjectHandle

	// Cipher block size
	blockSize int

	// Initialization vector
	iv []byte

	// block mechanism for encryption / decryption
	mechanism uint
}

// newBlockManager creates a new manager for block encryption/decryption operations
func (key *SecretKey) newBlockManager(mechanism uint, iv []byte) (*blockManager, error) {
	// pkcs11 contexte
	session, err := key.context.getSession()
	
	if err != nil {
		return nil, err
	}
	// iv
	if len(iv) != key.Cipher.BlockSize {
		return nil, fmt.Errorf("iv should have the same size as the algorithm block size. iv length was '%d' but "+
			"block size is '%d'", len(iv), key.Cipher.BlockSize)
	}
	// build block manager
	return &blockManager{
		session:   session,
		keyHandle: &key.handle,
		blockSize: key.Cipher.BlockSize,
		iv:        iv,
		mechanism: mechanism,
	}, nil
}

// NewBlockManagerCBC creates a new manager for block encryption/decryption operations using AES CBC without padding
// With this manager, be careful with the size of your
func (key *SecretKey) NewBlockManagerCBC(iv []byte) (BlockManager, error) {
	return key.newBlockManager(key.Cipher.CBCMech, iv)
}

// NewBlockManagerCBCPadding creates a new manager for block encryption/decryption operations using AES CBC with padding
func (key *SecretKey) NewBlockManagerCBCPadding(iv []byte) (BlockManager, error) {
	return key.newBlockManager(key.Cipher.CBCPKCSMech, iv)
}

// BlockSize returns the cipher's block size in bytes.
// DEPRECATED : you should use the BlockManager's method instead.
func (key *SecretKey) BlockSize() int {
	return key.Cipher.BlockSize
}

// BlockSize returns the cipher's block size in bytes.
func (bm *blockManager) BlockSize() int {
	return bm.blockSize
}

func (bm *blockManager) HasPadding() bool { return bm.mechanism == CipherAES.CBCPKCSMech }

// Decrypt decrypts in one go the ciphertext into a clear text in return.
// The ciphertext and the output buffers must overlap entirely or not at all.
//
// The mechanism given can be any symmetric block mechanism supported by this implementation in key.Cipher.
// Beware ! If you are not using a padding mechanism, the size of the ciphertext should be equal to the block size.
//
// Due to Block interface, this function does not return an error if the decryption fails.
// Logs are here to help to understand why such an operation should fail, but you should manage the different scenario
// of failure by yourself at upper stage.
//
// Using this method for bulk operation is very inefficient, as it makes a round trip to the HSM
// (which may be network-connected) for each block.
// For more efficient operation, see NewCBCDecrypterCloser, NewCBCDecrypter.
func (bm *blockManager) Decrypt(dst, src []byte) {
	// mechanism
	if bm.mechanism != CipherAES.CBCPKCSMech && len(src) != bm.blockSize {
		log.Printf("warning the size of the source buffer was '%d' bytes but must match a multiple of the block size of the current cipher: '%d' bytes", len(src), bm.blockSize)
		return
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(bm.mechanism, bm.iv)}
	// initialization of the decryption
	if err := bm.session.ctx.DecryptInit(bm.session.handle, mech, *bm.keyHandle); err != nil {
		log.Print("error during the initialization of the decryption for this session:", err)
		return
	}
	// decryption
	if result, err := bm.session.ctx.Decrypt(bm.session.handle, src); err != nil {
		log.Print("error during the decryption for this session:", err)
		return
	} else {
		if len(dst) < len(result) {
			log.Printf("warning the size of the desination buffer was '%d' bytes but is too small for result buffer size of '%d' bytes", len(dst), len(result))
			return
		}
		copy(dst[:len(result)], result)
	}
}

// Encrypt encrypts in one go the clear text into a ciphertext in return.
// The ciphertext and the output buffers must overlap entirely or not at all.
//
// The mechanism given can be any symmetric block mechanism supported by this implementation in key.Cipher.
// Beware ! If you are not using a padding mechanism, the size of the cleartext should be equal to the block size.
//
// Due to Block interface, this function does not return an error if the encryption fails.
// Logs are here to help to understand why such an operation should fail, but you should manage the different scenario
// of failure by yourself at upper stage.
//
// Using this method for bulk operation is very inefficient, as it makes a round trip to the HSM
// (which may be network-connected) for each block.
// For more efficient operation, see NewCBCEncrypterCloser, NewCBCEncrypter or NewCBC.
func (bm *blockManager) Encrypt(dst, src []byte) {
	// mechanism
	if bm.mechanism != CipherAES.CBCPKCSMech && len(src) % bm.blockSize != 0 {
		log.Printf("the size of the source buffer is '%d' bytes but must match a multiple of the block size of the current cipher: '%d' bytes", len(src), bm.blockSize)
		return
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(bm.mechanism, bm.iv)}
	// initialization of the encryption
	if err := bm.session.ctx.EncryptInit(bm.session.handle, mech, *bm.keyHandle); err != nil {
		log.Print("error during the initialization of the decryption for this session:", err)
		return
	}
	// encryption
	if result, err := bm.session.ctx.Encrypt(bm.session.handle, src); err != nil {
		log.Print("error during the decryption for this session:", err)
		return
	} else {
		if len(dst) < len(result) {
			log.Printf("the size of the desination buffer is '%d' bytes but is too small for result buffer size of '%d' bytes", len(dst), len(result))
			return
		}
		copy(dst[:len(result)], result)
	}
}
