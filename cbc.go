package crypto11

import (
	"log"
)

// Seal encrypts the source bytes to destination bytes as cipher data
func (key *SecretKey) Seal (dst []byte, src []byte, iv []byte) {
	encryptor, err := key.NewCBCEncrypterCloser(iv)
	if err != nil {
		panic("")
	}
	encryptor.CryptBlocks(dst, src)
	encryptor.Close()
	log.Print(dst)
}

// Open decrypts the source bytes to destination bytes as clear data
func (key *SecretKey) Open(dst []byte, src []byte, iv []byte) {
	decryptor, err := key.NewCBCDecrypterCloser(iv)
	if err != nil {
		panic("")
	}
	// CryptBlocks actually decrypts the src bytes
	// because NewCBCDecryptor sets the mechanism to 'decrypt' for block mode
	decryptor.CryptBlocks(dst, src)
	decryptor.Close()
	log.Print(dst)
}
