package cryptoutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	rand2 "math/rand"
	"strconv"
	"time"
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

	if len(paddedText) % aes.BlockSize != 0 {
		err = fmt.Errorf("paddedText [len=%d] is not a multiple of the block size", len(paddedText))
		return
	}

	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	ciphertext = make([]byte, aes.BlockSize + len(paddedText))
	iv := ciphertext[ : aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize : ], paddedText)

	return
}

// AesDecryptCBC defines aes decryption with CBC
func AesDecryptCBC(key, ciphertext []byte) (plaintext []byte, err error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = fmt.Errorf("ciphertext [len=%d] too short; should greater than blocksize", len(ciphertext))
		return
	}

	iv := ciphertext[ : aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize : ]

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	plaintext = unpad(ciphertext)

	return
}

// GenSessionKey generate a master key according to pair {key and data}
func GenMasterKey(key []byte, data []byte) (masterKey [] byte) {
	masterKey = genSessionKey(key, data)
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

	//fmt.Println("session key ", hex.EncodeToString(sessionKey), len(sessionKey))
	return
}

// Base64Encode encoding using base64
func Base64Encode(text []byte) (encodedText string) {
	encodedText = base64.StdEncoding.EncodeToString(text)
	return
}

// Base64Decode Decoding using base64
func Base64Decode(encodedText string) (text []byte, err error) {
	text, err = base64.StdEncoding.DecodeString(encodedText)
	return
}

// EncodeMessage encode a message with aes encrption, md5 signature
func EncodeMessage(plaintext []byte, key []byte) (message string, err error) {
	var cipher []byte

	// 8 for random number; 16 for md5 hash
	buffer := make([]byte, RandomNumberSize + CheckSumSize + len(plaintext))

	// add random
	random := rand2.Uint64()
	binary.LittleEndian.PutUint64(buffer[RandomNumberOffset : ], random)

	// add request body
	copy(buffer[MessageOffset : ], plaintext)

	// calculate and add checksum
	checksum := md5.Sum(buffer)
	copy(buffer[CheckSumOffset : ], checksum[ : ])

	// encryption with aes CBC with keysize of 256-bit
	if cipher, err = AesEncryptCBC(key, buffer); err != nil {
		return
	}
	// base64 encoding
	message = base64.StdEncoding.EncodeToString(cipher)
	fmt.Printf("EncodeMessge CBC: %s\n", message)
	return

}

// DecodeMessage decode a message and verify its validity
func DecodeMessage(message string, key []byte) (plaintext []byte, err error) {
	var (
		cipher      []byte
		decodedText []byte
	)

	if cipher, err = base64.StdEncoding.DecodeString(message); err != nil {
		return
	}

	if decodedText, err = AesDecryptCBC(key, cipher); err != nil {
		return
	}

	if len(decodedText) <= MessageMetaDataSize {
		err = fmt.Errorf("invalid json format with size [%d] less than message meta data size", len(decodedText))
		return
	}
	
	msgChecksum := make([]byte, CheckSumSize)
	copy(msgChecksum, decodedText[CheckSumOffset : CheckSumOffset + CheckSumSize])
	
	// calculate checksum
	filltext := bytes.Repeat([]byte{byte(0)}, CheckSumSize)
	copy(decodedText[CheckSumOffset : ], filltext[ : ])
	newChecksum := md5.Sum(decodedText)

	// verify checksum
	if bytes.Compare(msgChecksum, newChecksum[:]) != 0 {
		err = fmt.Errorf("checksum not match")
	}

	plaintext = decodedText[MessageOffset : ]

	fmt.Printf("DecodeMessage CBC: %s\n", plaintext)
	return
}