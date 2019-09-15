package authnode

import (
	"encoding/json"
	"net/http"
	"strconv"

	//"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/util/log"

	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	rand2 "math/rand"
	"time"
)

func keyNotFound(name string) (err error) {
	return errors.NewErrorf("parameter %v not found", name)
}

func sendErrReply(w http.ResponseWriter, r *http.Request, httpReply *proto.HTTPReply) {
	log.LogInfof("URL[%v],remoteAddr[%v],response err[%v]", r.URL, r.RemoteAddr, httpReply)
	reply, err := json.Marshal(httpReply)
	if err != nil {
		log.LogErrorf("fail to marshal http reply[%v]. URL[%v],remoteAddr[%v] err:[%v]", httpReply, r.URL, r.RemoteAddr, err)
		http.Error(w, "fail to marshal http reply", http.StatusBadRequest)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
	if _, err = w.Write(reply); err != nil {
		log.LogErrorf("fail to write http reply[%s] len[%d].URL[%v],remoteAddr[%v] err:[%v]", string(reply), len(reply), r.URL, r.RemoteAddr, err)
	}
	return
}

func (m *Server) extractClientInfo(r *http.Request) (client string, target string, err error) {
	if err = r.ParseForm(); err != nil {
		return
	}

	if client = r.FormValue(clientID); client == "" {
		err = keyNotFound(clientID)
		return
	}

	if target = r.FormValue(targetService); target == "" {
		err = keyNotFound(targetService)
		return
	}
	return
}

func (m *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	var (
		client string
		//ip       string
		target string
		err    error
	)

	if client, target, err = m.extractClientInfo(r); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Printf("clientID=%s service=%s\n", client, target)

	sendOkReply(w, r, newSuccessHTTPReply("Hello World!"))
}

func newSuccessHTTPReply(data interface{}) *proto.HTTPReply {
	return &proto.HTTPReply{Code: proto.ErrCodeSuccess, Msg: proto.ErrSuc.Error(), Data: data}
}

func sendOkReply(w http.ResponseWriter, r *http.Request, httpReply *proto.HTTPReply) (err error) {
	/*switch httpReply.Data.(type) {
	case *DataPartition:
		dp := httpReply.Data.(*DataPartition)
		dp.RLock()
		defer dp.RUnlock()
	case *MetaPartition:
		mp := httpReply.Data.(*MetaPartition)
		mp.RLock()
		defer mp.RUnlock()
	case *MetaNode:
		mn := httpReply.Data.(*MetaNode)
		mn.RLock()
		defer mn.RUnlock()
	case *DataNode:
		dn := httpReply.Data.(*DataNode)
		dn.RLock()
		defer dn.RUnlock()
	}*/
	reply, err := json.Marshal(httpReply)
	if err != nil {
		log.LogErrorf("fail to marshal http reply[%v]. URL[%v],remoteAddr[%v] err:[%v]", httpReply, r.URL, r.RemoteAddr, err)
		http.Error(w, "fail to marshal http reply", http.StatusBadRequest)
		return
	}
	send(w, r, reply)
	return
}

func send(w http.ResponseWriter, r *http.Request, reply []byte) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
	if _, err := w.Write(reply); err != nil {
		log.LogErrorf("fail to write http reply[%s] len[%d].URL[%v],remoteAddr[%v] err:[%v]", string(reply), len(reply), r.URL, r.RemoteAddr, err)
		return
	}
	log.LogInfof("URL[%v],remoteAddr[%v],response ok", r.URL, r.RemoteAddr)
	return
}

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
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	//iv, _ := hex.DecodeString("acfa7a047800b2f221f2c4f7d626eafb")
	//copy(ciphertext[:aes.BlockSize], iv)

	fmt.Printf("CBC Key: %s\n", hex.EncodeToString(key))
	fmt.Printf("CBC IV: %s\n", hex.EncodeToString(iv))

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return
}

func decryptCBC(key, ciphertext []byte) (plaintext []byte, err error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		fmt.Printf("ciphertext too short")
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	plaintext = ciphertext

	return
}

func createReq2(req []byte) (message string) {
	var cipher []byte
	var err error
	key := []byte("11111111111111111111111111111111")

	plaintext := make([]byte, 8+16+8+len(req))
	random := rand2.Uint64()

	// add random
	binary.LittleEndian.PutUint64(plaintext, random)
	// add timestamp
	binary.LittleEndian.PutUint64(plaintext[8+16:], uint64(time.Now().Unix()))
	// add request body
	copy(plaintext[8+16+8:], req)
	fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))
	checksum := md5.Sum(plaintext)
	fmt.Printf("checksum=%s\n", base64.StdEncoding.EncodeToString(checksum[:]))
	copy(plaintext[8:], checksum[:])
	fmt.Printf("plaintext=%s %d\n", base64.StdEncoding.EncodeToString(plaintext), len(plaintext))

	if cipher, err = encryptCBC(key, Pad(plaintext)); err != nil {
		panic(err)
	}

	message = base64.StdEncoding.EncodeToString(cipher)
	fmt.Printf("CBC: %s\n", message)

	return
}

func checkMessage2(message string) {
	var cipher []byte
	var err error
	key := []byte("11111111111111111111111111111111")
	var paddingtext []byte

	if cipher, err = base64.StdEncoding.DecodeString(message); err != nil {
		panic(err)
	}

	if paddingtext, err = decryptCBC(key, cipher); err != nil {
		panic(err)
	}

	plaintext := Unpad(paddingtext)
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

}
