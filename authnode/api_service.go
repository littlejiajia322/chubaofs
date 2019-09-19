package authnode

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	//"strings"
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

func extractJSONByteArray(plaintext []byte) (jarray []byte, err error) {
	if len(plaintext) <= 8+16 {
		err = fmt.Errorf("invalid json input")
		return
	}
	jarray = make([]byte, len(plaintext)-16-8)
	copy(jarray, plaintext[8+16:])
	return
}

var keymap = map[string]string{"client1": "11111111111111111111111111111111", "master": "22222222222222222222222222222222"}
var authMasterKey = "33333333333333333333333333333333"

func getIPAdress(r *http.Request) string {
    var ipAddress string
    for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
        for _, ip := range strings.Split(r.Header.Get(h), ",") {
            // header can contain spaces too, strip those out.
            realIP := net.ParseIP(strings.Replace(ip, " ", "", -1))
            ipAddress = string(realIP)
        }
    }
    return ipAddress
}

func genTicket(serviceID proto.ServiceID, IP []byte, caps []byte) (ticket proto.Ticket) {
	currentTime := time.Now().Unix()
	ticket.Version = ticketVersion
	ticket.ServiceID = serviceID
	ticket.SessionKey.Ctime = currentTime
	ticket.SessionKey.Key = cryptoutil.AuthGenSessionKeyTS([]byte(authMasterKey))
	ticket.Exp = currentTime + ticketExpiration //TODO const
	ticket.IP = IP
	ticket.Caps = caps
	return
}

func genClientAuthResponse(clientID string, ts int64, serviceID proto.ServiceID, r *http.Request) (message string, err error) {
	var (
		jticket []byte
		jresp []byte
		resp proto.MsgClientAuthResp
	)

	resp.Type = proto.ServiceID2MsgRespMap[serviceID]
	resp.ClientID = clientID
	resp.ServiceID = serviceID
	resp.IP = getIPAdress(r)
	resp.Ts = ts + 1;
	ticket := genTicket(serviceID, []byte(resp.IP), []byte(`{"master":"yes"}`))
	resp.SessionKey = ticket.SessionKey

	if jticket, err = json.Marshal(ticket); err != nil {
		return
	}
	// TODO key
	key := []byte(keymap[proto.ServiceID2NameMap[serviceID]])
	if resp.Ticket, err = cryptoutil.EncodeMessage(jticket, key); err != nil {
		return
	}

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, []byte(authMasterKey)); err != nil {
		return
	}

	return
}

func (m *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	var (
		client string
		//ip       string
		message   string
		plaintext []byte
		jarray    []byte
		err       error
		jobj      proto.MsgClientAuthReq
	)

	if client, message, err = m.extractClientInfo(r); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Printf("clientID=%s message=%s\n", client, message)

	// TODO: check db
	if _, ok := keymap[client]; !ok {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: fmt.Sprintf("clientID=%s not existing!", client)})
		return
	}
	key := []byte(keymap[client])

	if plaintext, err = cryptoutil.DecodeMessage(message, key); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeMSGDecodeError, Msg: err.Error()})
		return
	}

	if jarray, err = extractJSONByteArray(plaintext); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}
	fmt.Println(string(jarray) + "\n")

	if err = json.Unmarshal(jarray, &jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Println(jobj.ClientID, jobj.IP, jobj.ServiceID)

	if time.Now().Unix()-jobj.Ts >= 5*60 { // TODO: const
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("req ts is timeout").Error()})
		return
	}

	if !proto.IsValidServiceID(jobj.ServiceID) {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("invalid service ID").Error()})
		return
	}

	if !proto.IsValidMsgReqType(jobj.ServiceID, jobj.Type) {
		sendErrReply(w, r, &proto.HTTPReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("invalid request type").Error()})
		return
	}



	sendOkReply(w, r, newSuccessHTTPReply(`"key":"Hello World!"`))
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
