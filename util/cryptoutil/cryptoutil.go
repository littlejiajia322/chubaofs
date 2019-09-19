package cryptoutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"
	"strconv"
	"crypto/md5"
	"encoding/base64"
	rand2 "math/rand"
	"encoding/binary"
)

func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// AesEncryptCBC defines aes encryption with CBC
func AesEncryptCBC(key, plaintext []byte) (ciphertext []byte, err error) {
	var (
		block cipher.Block
	)

	if plaintext == nil || len(plaintext) == 0 {
		err = fmt.Errorf("input for encryption is invalid")
		return
	}

	paddedText := pad(plaintext)

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

// AesDecryptCBC defines aes decryption with CBC
func AesDecryptCBC(key, ciphertext []byte) (plaintext []byte, err error) {
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

	plaintext = unpad(ciphertext)

	return
}

func genSessionKey(key []byte, data []byte) (sessionKey []byte) {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	sessionKey = h.Sum(nil)
	return
}

// AuthGenSessionKeyTS authnode generates a session key according to its master key and current timestamp
func AuthGenSessionKeyTS(key []byte) (sessionKey []byte) {
	data := []byte(strconv.FormatInt(int64(time.Now().Unix()), 10))
	sessionKey = genSessionKey(key, data)
	sha := hex.EncodeToString(sessionKey)

	fmt.Println("session key = %s\nsize=%d\n" + sha, len(sessionKey))
	return
}

// EncodeMessage encode a message with aes encrption, md5 signature
func EncodeMessage(plaintext []byte, key []byte) (message string, err error) {
	var cipher []byte

	// 8 for random number; 16 for md5 hash
	buffer := make([]byte, 8 + 16 + len(plaintext)) // TODO const
	// add random
	random := rand2.Uint64()
	binary.LittleEndian.PutUint64(buffer, random)
	// add request body
	copy(buffer[8 + 16:], plaintext) // TODO const
	//fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))
	// calculate and add md5
	checksum := md5.Sum(buffer)
	//fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum[:]))
	copy(buffer[8:], checksum[:])
	//fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))
	// encryption with aes CBC with keysize of 256-bit
	if cipher, err = AesEncryptCBC(key, buffer); err != nil {
		return
	}
	// base64 encoding
	message = base64.StdEncoding.EncodeToString(cipher)
	fmt.Printf("CBC: %s\n", message)
	return

}

// DecodeMessage decode a message and verify its validity
func DecodeMessage(message string, key []byte) (plaintext []byte, err error) {
	var (
		cipher []byte
	)

	if cipher, err = base64.StdEncoding.DecodeString(message); err != nil {
		return
	}

	if plaintext, err = AesDecryptCBC(key, cipher); err != nil {
		return
	}

	checksum2 := make([]byte, 16)
	copy(checksum2, plaintext[8:24])
	//fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum2))
	filltext := bytes.Repeat([]byte{byte(0)}, 16)
	copy(plaintext[8:], filltext[:])
	//fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))
	checksum3 := md5.Sum(plaintext)
	//fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum2))
	//fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum3[:]))

	// verify checksum
	if bytes.Compare(checksum2, checksum3[:]) != 0 {
		err = fmt.Errorf("MD5 not matched")
	}

	return
}
