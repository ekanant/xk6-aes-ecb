package aesecb

import (
	"crypto/aes"
	"fmt"
)

type AesEcb struct{}

// AES-ECB encrypt
// The key argument must be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func (AesEcb) Encrypt(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plainText)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("plaintext is not a multiple of block size")
	}

	cipherText := make([]byte, len(plainText))
	for start := 0; start < len(plainText); start += block.BlockSize() {
		block.Encrypt(cipherText[start:start+block.BlockSize()], plainText[start:start+block.BlockSize()])
	}
	return cipherText, nil
}

func (c AesEcb) EncryptWithPad(plainText, key []byte, blockSize int, padStyle string) ([]byte, error) {
	plainTextPad, err := c.Pad(plainText, blockSize, padStyle)
	if err != nil {
		panic(err)
	}
	return c.Encrypt(plainTextPad, key)
}

// AES-ECB decrypt
// The key argument must be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func (AesEcb) Decrypt(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plainText := make([]byte, len(cipherText))
	for start := 0; start < len(cipherText); start += block.BlockSize() {
		block.Decrypt(plainText[start:start+block.BlockSize()], cipherText[start:start+block.BlockSize()])
	}
	return plainText, nil
}

func (c AesEcb) DecryptWithUnPad(cipherText, key []byte, blockSize int, padStyle string) ([]byte, error) {
	enCryptedWithPad, err := c.Decrypt([]byte(cipherText), key)
	if err != nil {
		panic(err)
	}

	enCryptedUnPad, err := c.Unpad(enCryptedWithPad, blockSize, padStyle)
	if err != nil {
		panic(err)
	}
	return enCryptedUnPad, nil
}
