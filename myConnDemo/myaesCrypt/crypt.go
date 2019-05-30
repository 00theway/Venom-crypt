package myaesCrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func aes256key() []byte {
	key := []byte("passw0rdpassw0rdpassw0rdpassw0rd")
	return key
}

type RecordCrypt interface {
	Encrypt(dst, plaintext []byte) ([]byte, error)
	Decrypt(dst, cipertext []byte) ([]byte, error)
}

type AesCrypt struct{}

func (hrc *AesCrypt) Encrypt(dst, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(aes256key())
	if err != nil {
		return nil, err
	}

	dst = make([]byte, aes.BlockSize+len(plainText))
	iv := dst[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(dst[aes.BlockSize:], plainText)
	return dst, nil
}

func (hrc *AesCrypt) Decrypt(dst, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(aes256key())
	if err != nil {
		return nil, err
	}

	decryptedText := make([]byte, len(cipherText[aes.BlockSize:]))
	decryptStream := cipher.NewCTR(block, cipherText[:aes.BlockSize])
	decryptStream.XORKeyStream(decryptedText, cipherText[aes.BlockSize:])
	return decryptedText, nil
}
