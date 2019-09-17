package authnode

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	//"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/util/log"

	"fmt"
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

func (m *Server) extractClientInfo(r *http.Request) (client string, message string, err error) {
	if err = r.ParseForm(); err != nil {
		return
	}

	if client = r.FormValue(clientID); client == "" {
		err = keyNotFound(clientID)
		return
	}

	if message = r.FormValue(encryptedMessage); message == "" {
		err = keyNotFound(encryptedMessage)
		return
	}
	return
}

func decodeMessage(message string, key []byte) (plaintext []byte, err error) {
	var (
		cipher []byte
	)

	if cipher, err = base64.StdEncoding.DecodeString(message); err != nil {
		return
	}

	if plaintext, err = cryptoutil.AesDecryptCBC(key, cipher); err != nil {
		return
	}
	return
}

func verifyMessage(plaintext []byte, key []byte) (err error) {
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

func extractJsonByteArray(plaintext []byte) (jarray []byte, err error) {
	if len(plaintext) <=  8 + 16 {
		err = fmt.Errorf("invalid json input")
		return
	}
	jarray = make([]byte, len(plaintext) - 16 - 8)
	copy(jarray, plaintext[8 + 16:])
	return
}

type MsgClientAuthReq struct {
	ClientID string `json:"ClientID"`
	Service  string `json:"Service"`
	Ip       string `json:"Ip"`
	Ts       int64  `json:"Ts"`
}

var key_map = map[string]string{"client1": "11111111111111111111111111111111", "master": "22222222222222222222222222222222"}

func (m *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	var (
		client string
		//ip       string
		message   string
		plaintext []byte
		jarray    []byte
		err       error
		jobj      MsgClientAuthReq
	)

	if client, message, err = m.extractClientInfo(r); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Printf("clientID=%s message=%s\n", client, message)

	// TODO: check db
	if _, ok := key_map[client]; !ok {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: fmt.Sprintf("clientID=%s not existing!", client)})
		return
	}
	key := []byte(key_map[client])

	if plaintext, err = decodeMessage(message, key); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeMSGDecodeError, Msg: err.Error()})
		return
	}

	if err = verifyMessage(plaintext, key); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeMSGVerifyError, Msg: err.Error()})
		return
	}

	if jarray, err = extractJsonByteArray(plaintext); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}
	fmt.Println(string(jarray) + "\n")

	if err = json.Unmarshal(jarray, &jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Println(jobj.ClientID, jobj.Ip, jobj.Service)

	if time.Now().Unix()-jobj.Ts >= 5 * 60 { // TODO: const
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("req ts is timeout").Error()})
		return
	}
	if strings.Compare(jobj.Service, "master") != 0 && strings.Compare(jobj.Service, "metanode") != 0 && strings.Compare(jobj.Service, "datanode") != 0 {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPReply("Hello World!"))
	return
}

func newSuccessHTTPReply(data interface{}) *proto.HTTPReply {
	return &proto.HTTPReply{Code: proto.ErrCodeSuccess, Msg: proto.ErrSuc.Error(), Data: data}
}

func sendOkReply(w http.ResponseWriter, r *http.Request, httpReply *proto.HTTPReply) (err error) {
	/*switch httpReply.Data.(type) {
	case *DataPartition:
		dp := httpReply.Data.(*DataPartition)Block
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
