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
	"fmt"

	"github.com/miekg/pkcs11"
)

// Block
// Use these function to encrypt/decrypt cleartext/ciphertext in one go.
// This approach is simple but lack of efficiency for bulk operations.
// For a more efficient approach, check BlockMode instead.

// BlockSize returns the cipher's block size in bytes.
func (key *SecretKey) BlockSize() int {
	return key.Cipher.BlockSize
}

func checkIvSize(key *SecretKey, iv []byte) error {
	if len(iv) != key.Cipher.BlockSize {
		return fmt.Errorf("iv should have the same size as the algorithm block size. iv length was '%d' but " +
			"block size is '%d'", len(iv), key.Cipher.BlockSize)
	}
	return nil
}

// Decrypt decrypts in one go the ciphertext into a clear text in return.
// The ciphertext and the output buffers must overlap entirely or not at all.
// The IV given to decrypt should :
//   - be the same as the IV used to encrypt the original text in the ciphertext
//   - have the same size as the block size of the cipher for the given key.
// The mechanism given can be any symmetric block mechanism supported by this implementation in key.Cipher.
// Beware ! If you are not using a padding mechanism, the size of the ciphertext should be equal to the block size.
//
// Using this method for bulk operation is very inefficient, as it makes a round trip to the HSM
// (which may be network-connected) for each block.
// For more efficient operation, see NewCBCDecrypterCloser, NewCBCDecrypter.
func (key *SecretKey) Decrypt(mechanism uint, iv, ciphertext []byte) ([]byte, error) {
	if err := checkIvSize(key, iv); err != nil {
		return nil, err
	}
	var result []byte
	if err := key.context.withSession(func(session *pkcs11Session) (err error) {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}
		if err = session.ctx.DecryptInit(session.handle, mech, key.handle); err != nil {
			return
		}
		if result, err = session.ctx.Decrypt(session.handle, ciphertext); err != nil {
			return
		}
		return
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// Encrypt encrypts in one go the clear text into a ciphertext in return.
// The ciphertext and the output buffers must overlap entirely or not at all.
// The IV given to decrypt should :
//   - be the same as the IV used to encrypt the original text in the ciphertext
//   - have the same size as the block size of the cipher for the given key.
// The mechanism given can be any symmetric block mechanism supported by this implementation in key.Cipher.
// Beware ! If you are not using a padding mechanism, the size of the cleartext should be equal to the block size.
//
// Using this method for bulk operation is very inefficient, as it makes a round trip to the HSM
// (which may be network-connected) for each block.
// For more efficient operation, see NewCBCEncrypterCloser, NewCBCEncrypter or NewCBC.
func (key *SecretKey) Encrypt(mechanism uint, iv, cleartext []byte) ([]byte, error) {
	if err := checkIvSize(key, iv); err != nil {
		return nil, err
	}
	var result []byte
	if err := key.context.withSession(func(session *pkcs11Session) (err error) {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}
		if err = session.ctx.EncryptInit(session.handle, mech, key.handle); err != nil {
			return
		}
		if result, err = session.ctx.Encrypt(session.handle, cleartext); err != nil {
			return
		}
		return
	}); err != nil {
		return nil, err
	}
	return result, nil
}
