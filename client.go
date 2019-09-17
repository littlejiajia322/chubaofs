package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	rand2 "math/rand"
	"net/http"
	"net/url"
	"time"
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

func createEncReq(req []byte, key []byte) (message string, err error) {
	var cipher []byte

	// 8 for random number; 16 for md5 hash
	plaintext := make([]byte, 8+16+len(req))
	// add random
	random := rand2.Uint64()
	binary.LittleEndian.PutUint64(plaintext, random)
	// add request body
	copy(plaintext[8+16:], req)
	fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))
	// calculate and add md5
	checksum := md5.Sum(plaintext)
	fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum[:]))
	copy(plaintext[8:], checksum[:])
	fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))
	// encryption with aes CBC with keysize of 256-bit
	if cipher, err = encryptCBC(key, plaintext); err != nil {
		return
	}
	// base64 encoding
	message = base64.StdEncoding.EncodeToString(cipher)
	fmt.Printf("CBC: %s\n", message)
	return
}

func verifyMessage(message string, key []byte) (err error) {
	var (
		cipher    []byte
		plaintext []byte
	)

	if cipher, err = base64.StdEncoding.DecodeString(message); err != nil {
		return
	}

	if plaintext, err = decryptCBC(key, cipher); err != nil {
		return
	}

	//plaintext := Unpad(paddingtext)
	fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))

	checksum2 := make([]byte, 16)
	copy(checksum2, plaintext[8:24])
	fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum2))
	filltext := bytes.Repeat([]byte{byte(0)}, 16)
	copy(plaintext[8:], filltext[:])
	fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))
	checksum3 := md5.Sum(plaintext)
	fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum2))
	fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum3[:]))

	if bytes.Compare(checksum2, checksum3[:]) != 0 {
		panic("not equal")
	}
	return
}

type authEncReq struct {
	ClientID string
	Service  string
	Ip       string
	Ts       int64
}

func main() {
	var (
		err          error
		message_json []byte
		message      string
	)
	clientID := "client1"
	service := "master"
	ip := "123456789"
	ts := time.Now().Unix()
	// construct request body
	message_struct := authEncReq{ClientID: clientID, Service: service, Ip: ip, Ts: ts}
	var message_struct2 authEncReq
	if message_json, err = json.Marshal(message_struct); err != nil {
		panic(err)
	}
	fmt.Printf(string(message_json) + "\n")

	if err = json.Unmarshal(message_json, &message_struct2); err != nil {
		panic(err)
	}
	fmt.Printf("%s %s %s \n", message_struct2.ClientID, message_struct2.Ip, message_struct2.Service)

	// encrption
	message, err = createEncReq(message_json, []byte("11111111111111111111111111111111"))
	if err != nil {
		panic(err)
	}

	if err = verifyMessage(message, []byte("11111111111111111111111111111111")); err != nil {
		panic(err)
	}

	// We can use POST form to get result, too.
	resp, err := http.PostForm("http://localhost:8081/client/getticket",
		url.Values{"ClientID": {"client1"}, "Message": {message}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		panic(err2)
	}
	//fmt.Println("post:\n", keepLines(string(body), 3))
	fmt.Printf("respose: %s", string(body))

	return
}
