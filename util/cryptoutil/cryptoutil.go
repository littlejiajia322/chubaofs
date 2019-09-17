package cryptoutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// CBC
func encryptCBC(key, plaintext []byte) (ciphertext []byte, err error) {
	var (
		block cipher.Block
	)

	if plaintext == nil || len(plaintext) == 0 {
		err = fmt.Errorf("input for encryption is invalid")
		return
	}

	paddedText := Pad(plaintext)

	if len(paddedText)%aes.BlockSize != 0 {
		err = fmt.Errorf("paddedText [len=%d] is not a multiple of the block size", len(paddedText))
		return
	}

	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	ciphertext = make([]byte, aes.BlockSize+len(paddedText))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	//fmt.Printf("CBC Key: %s\n", hex.EncodeToString(key))
	//fmt.Printf("CBC IV: %s\n", hex.EncodeToString(iv))

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], paddedText)

	return
}

func decryptCBC(key, ciphertext []byte) (plaintext []byte, err error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = fmt.Errorf("ciphertext [len=%d] too short", len(ciphertext))
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	plaintext = Unpad(ciphertext)

	return
}
