package authnode

import (
	"encoding/json"
	"net/http"
	"strconv"


	//"strings"
	"time"

	//"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/util/log"
	"github.com/chubaofs/chubaofs/util/iputil"

	"fmt"
)

func keyNotFound(name string) (err error) {
	return errors.NewErrorf("parameter %v not found", name)
}

func sendErrReply(w http.ResponseWriter, r *http.Request, HTTPGetTicketAuthReply *proto.HTTPGetTicketAuthReply) {
	log.LogInfof("URL[%v],remoteAddr[%v],response err[%v]", r.URL, r.RemoteAddr, HTTPGetTicketAuthReply)
	reply, err := json.Marshal(HTTPGetTicketAuthReply)
	if err != nil {
		log.LogErrorf("fail to marshal http reply[%v]. URL[%v],remoteAddr[%v] err:[%v]", HTTPGetTicketAuthReply, r.URL, r.RemoteAddr, err)
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

var authMasterKey = "33333333333333333333333333333333"

func genTicket(serviceID proto.ServiceID, IP []byte, caps []byte) (ticket proto.Ticket) {
	currentTime := time.Now().Unix()
	ticket.Version = ticketVersion
	ticket.ServiceID = serviceID
	ticket.SessionKey.Ctime = currentTime
	ticket.SessionKey.Key = cryptoutil.AuthGenSessionKeyTS([]byte(authMasterKey))
	ticket.Exp = currentTime + ticketDuration
	ticket.IP = IP
	ticket.Caps = caps
	return
}

func genClientGetTicketAuthResponse(req *proto.MsgClientGetTicketAuthReq, r *http.Request) (message string, err error) {
	var (
		jticket []byte
		jresp   []byte
		resp    proto.MsgClientGetTicketAuthResp
	)

	resp.Type = proto.ServiceID2MsgRespMap[req.ServiceID]
	resp.ClientID = req.ClientID
	resp.ServiceID = req.ServiceID
	resp.IP = iputil.RealIP(r)
	resp.Ts = req.Ts + 1
	ticket := genTicket(resp.ServiceID, []byte(resp.IP), []byte(`{"master":"yes"}`))
	resp.SessionKey = ticket.SessionKey

	if jticket, err = json.Marshal(ticket); err != nil {
		return
	}
	// Use service key to encrypt ticket
	// TODO key
	key := []byte(keymap[proto.ServiceID2NameMap[resp.ServiceID]])
	fmt.Printf("serviceID=%d serviceName=%s key=%d\n", resp.ServiceID, proto.ServiceID2NameMap[resp.ServiceID], len(key))
	if resp.Ticket, err = cryptoutil.EncodeMessage(jticket, key); err != nil {
		return
	}

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	// Use client key to encrypt response message
	// TODO key
	if message, err = cryptoutil.EncodeMessage(jresp, []byte(keymap[resp.ClientID])); err != nil {
		return
	}

	return
}

func (m *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	var (
		client string
		message      string
		plaintext    []byte
		err          error
		jobj         proto.MsgClientGetTicketAuthReq
	)

	if client, message, err = m.extractClientInfo(r); err != nil {
		sendErrReply(w, r, &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Printf("clientID=%s message=%s\n", client, message)

	// TODO: check db
	if _, ok := keymap[client]; !ok {
		sendErrReply(w, r, &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeParamError, Msg: fmt.Sprintf("clientID=%s not existing!", client)})
		return
	}
	key := []byte(keymap[client])

	if plaintext, err = cryptoutil.DecodeMessage(message, key); err != nil {
		sendErrReply(w, r, &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeMSGDecodeError, Msg: err.Error()})
		return
	}

	if err = json.Unmarshal(plaintext, &jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Println(jobj.ClientID, jobj.ServiceID)

	if time.Now().Unix() - jobj.Ts >= ticketReqDuration {
		sendErrReply(w, r, &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("ticket req is timeout").Error()})
		return
	}

	if !proto.IsValidServiceID(jobj.ServiceID) {
		sendErrReply(w, r, &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("invalid service ID").Error()})
		return
	}

	if !proto.IsValidMsgReqType(jobj.ServiceID, jobj.Type) {
		sendErrReply(w, r, &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("invalid request type").Error()})
		return
	}

	// TODO check whether jobj.ip == the IP from HTTP request
	if message, err = genClientGetTicketAuthResponse(&jobj, r); err != nil {
		sendErrReply(w, r, &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	sendOkReply(w, r, newSuccessHTTPGetTicketAuthReply(message))
	return
}

func newSuccessHTTPGetTicketAuthReply(data interface{}) *proto.HTTPGetTicketAuthReply {
	return &proto.HTTPGetTicketAuthReply{Code: proto.ErrCodeSuccess, Msg: proto.ErrSuc.Error(), Data: data}
}

func sendOkReply(w http.ResponseWriter, r *http.Request, HTTPGetTicketAuthReply *proto.HTTPGetTicketAuthReply) (err error) {
	/*switch HTTPGetTicketAuthReply.Data.(type) {
	case *DataPartition:
		dp := HTTPGetTicketAuthReply.Data.(*DataPartition)Block
		dp.RLock()
		defer dp.RUnlock()
	case *MetaPartition:
		mp := HTTPGetTicketAuthReply.Data.(*MetaPartition)
		mp.RLock()
		defer mp.RUnlock()
	case *MetaNode:
		mn := HTTPGetTicketAuthReply.Data.(*MetaNode)
		mn.RLock()
		defer mn.RUnlock()
	case *DataNode:
		dn := HTTPGetTicketAuthReply.Data.(*DataNode)
		dn.RLock()
		defer dn.RUnlock()
	}*/
	reply, err := json.Marshal(HTTPGetTicketAuthReply)
	if err != nil {
		log.LogErrorf("fail to marshal http reply[%v]. URL[%v],remoteAddr[%v] err:[%v]", HTTPGetTicketAuthReply, r.URL, r.RemoteAddr, err)
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
