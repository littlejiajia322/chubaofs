package authnode

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strconv"

	//"strings"
	"time"

	//"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/caps"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/util/iputil"
	"github.com/chubaofs/chubaofs/util/keystore"
	"github.com/chubaofs/chubaofs/util/log"

	"fmt"
)

func (m *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.AuthGetTicketReq
		ts        int64
		keyInfo   keystore.KeyInfo
		message   string
	)

	if plaintext, err = m.extractClientReqInfo(r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Printf("message=%s\n", plaintext)

	if err = json.Unmarshal([]byte(plaintext), &jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if keyInfo, err = keystore.GetKeyInfo(jobj.ClientID); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if ts, err = parseVerifier(jobj.Verifier, keyInfo.Key); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if err = validateGetTicketReqFormat(&jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	// TODO check whether jobj.ip == the IP from HTTP request
	if message, err = m.genGetTicketAuthResp(&jobj, ts, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))
	return
}

func (m *Server) apiAccessEntry(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext  []byte
		err        error
		jobj       proto.AuthAPIAccessReq
		ticket     cryptoutil.Ticket
		ts         int64
		newKeyInfo *keystore.KeyInfo
		message    string
	)

	if plaintext, err = m.extractClientReqInfo(r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Printf("message=%s\n", plaintext)

	if err = json.Unmarshal([]byte(plaintext), &jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "Unmarshal AuthAPIAccessReq failed: " + err.Error()})
		return
	}

	apiReq := jobj.APIReq
	keyInfo := jobj.KeyInfo

	if err = keyInfo.IsValidID(); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	switch apiReq.Type {
	case proto.MsgAuthCreateKeyReq:
		if err = keyInfo.IsValidKeyInfo(); err != nil {
			sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		}
	case proto.MsgAuthDeleteKeyReq:
	case proto.MsgAuthGetKeyReq:
	//case proto.MsgAuthGetCapsReq:
	case proto.MsgAuthAddCapsReq:
		fallthrough
	case proto.MsgAuthDeleteCapsReq:
		if err = keyInfo.IsValidCaps(); err != nil {
			sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		}
	default:
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("invalid request messge type %x", int32(apiReq.Type)).Error()})
	}

	if err = proto.IsValidClientID(apiReq.ClientID); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "IsValidClientID failed: " + err.Error()})
		return
	}

	if err = proto.IsValidServiceID(apiReq.ServiceID); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "IsValidServiceID failed: " + err.Error()})
		return
	}

	if err = proto.IsValidMsgReqType(apiReq.ServiceID, apiReq.Type); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "IsValidMsgReqType failed: " + err.Error()})
		return
	}

	masterKey := keystore.AuthMasterKey

	if ticket, err = extractTicket(apiReq.Ticket, masterKey); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "extractTicket failed: " + err.Error()})
		return
	}

	if ts, err = parseVerifier(apiReq.Verifier, ticket.SessionKey.Key); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "parseVerifier failed: " + err.Error()})
		return
	}

	if _, ok := proto.MsgType2ResourceMap[apiReq.Type]; !ok {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "MsgType2ResourceMap failed"})
		return
	}

	resource := proto.MsgType2ResourceMap[apiReq.Type]

	if err = checkTicketCaps(&ticket, "API", resource); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "checkTicketCaps failed: " + err.Error()})
		return
	}

	switch apiReq.Type {
	case proto.MsgAuthCreateKeyReq:
		newKeyInfo, err = m.handleCreateKey(&keyInfo)
	case proto.MsgAuthDeleteKeyReq:
		newKeyInfo, err = m.handleDeleteKey(&keyInfo)
	case proto.MsgAuthGetKeyReq:
		newKeyInfo, err = m.handleGetKey(&keyInfo)
	//case proto.MsgAuthGetCapsReq:
	//newKeyInfo, err = m.handleGetCaps(&keyInfo)
	case proto.MsgAuthAddCapsReq:
		newKeyInfo, err = m.handleAddCaps(&keyInfo)
	case proto.MsgAuthDeleteCapsReq:
		newKeyInfo, err = m.handleDeleteCaps(&keyInfo)
	}

	if err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeAuthKeyStoreError, Msg: err.Error()})
		return
	}

	if message, err = genAuthAPIAccessResp(&apiReq, newKeyInfo, ts, ticket.SessionKey.Key); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeAuthAPIAccessGenRespError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))

}

func (m *Server) handleCreateKey(keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	if res, err = m.cluster.CreateNewKey(keyInfo.ID, keyInfo); err != nil {
		return
	}
	return
}

func (m *Server) handleDeleteKey(keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	if res, err = m.cluster.DeleteKey(keyInfo.ID); err != nil {
		return
	}
	return
}

func (m *Server) handleGetKey(keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	if res, err = m.cluster.GetKey(keyInfo.ID); err != nil {
		return
	}
	return
}

func (m *Server) handleAddCaps(keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	if res, err = m.cluster.AddCaps(keyInfo.ID, keyInfo); err != nil {
		return
	}
	return
}

func (m *Server) handleDeleteCaps(keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	if res, err = m.cluster.DeleteCaps(keyInfo.ID, keyInfo); err != nil {
		return
	}
	return
}

func (m *Server) extractClientReqInfo(r *http.Request) (plaintext []byte, err error) {
	var (
		message string
	)
	if err = r.ParseForm(); err != nil {
		return
	}

	if message = r.FormValue(ClientMessage); message == "" {
		err = keyNotFound(ClientMessage)
		return
	}

	if plaintext, err = cryptoutil.Base64Decode(message); err != nil {
		return
	}

	return
}

func (m *Server) genTicket(key []byte, serviceID string, IP string, caps []byte) (ticket cryptoutil.Ticket) {
	currentTime := time.Now().Unix()
	ticket.Version = TicketVersion
	ticket.ServiceID = serviceID
	ticket.SessionKey.Ctime = currentTime
	ticket.SessionKey.Key = cryptoutil.AuthGenSessionKeyTS(key)
	ticket.Exp = currentTime + TicketDuration
	ticket.IP = IP
	ticket.Caps = caps
	return
}

func (m *Server) getServiceKey(serviceID string) (key []byte, err error) {
	if serviceID == proto.AuthServiceID {
		key = keystore.AuthMasterKey
	} else {
		if key, err = keystore.GetMasterKey(serviceID); err != nil {
			return
		}
	}
	return
}

func (m *Server) genGetTicketAuthResp(req *proto.AuthGetTicketReq, ts int64, r *http.Request) (message string, err error) {
	var (
		jticket    []byte
		jresp      []byte
		resp       proto.AuthGetTicketResp
		serviceKey []byte
		clientKey  []byte
		caps       []byte
	)

	resp.Type = req.Type + 1
	resp.ClientID = req.ClientID
	resp.ServiceID = req.ServiceID
	// increase ts by one for client verify server
	resp.Verifier = ts + 1
	if caps, err = keystore.GetCaps(resp.ClientID); err != nil {
		return
	}
	// Use service key to encrypt ticket
	if serviceKey, err = m.getServiceKey(req.ServiceID); err != nil {
		return
	}

	ticket := m.genTicket(serviceKey, resp.ServiceID, iputil.RealIP(r), caps)
	resp.SessionKey = ticket.SessionKey

	if jticket, err = json.Marshal(ticket); err != nil {
		return
	}

	fmt.Printf("serviceID=%s serviceName=%s key=%d\n", resp.ServiceID, resp.ServiceID, len(serviceKey))

	if resp.Ticket, err = cryptoutil.EncodeMessage(jticket, serviceKey); err != nil {
		return
	}

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	// Use client master key to encrypt response message
	if clientKey, err = keystore.GetMasterKey(resp.ClientID); err != nil {
		return
	}
	if message, err = cryptoutil.EncodeMessage(jresp, clientKey); err != nil {
		return
	}

	return
}

func parseVerifier(verifier string, key []byte) (ts int64, err error) {
	var (
		plainttext []byte
	)

	fmt.Printf("verifier=%s\n", verifier)
	if plainttext, err = cryptoutil.DecodeMessage(verifier, key); err != nil {
		return
	}

	ts = int64(binary.LittleEndian.Uint64(plainttext))

	if time.Now().Unix()-ts >= TicketReqDuration {
		err = fmt.Errorf("ticket req is timeout") // TODO
		return
	}

	return
}

func validateGetTicketReqFormat(req *proto.AuthGetTicketReq) (err error) {
	if err = proto.IsValidClientID(req.ClientID); err != nil {
		return
	}

	if err = proto.IsValidServiceID(req.ServiceID); err != nil {
		return
	}

	if err = proto.IsValidMsgReqType(req.ServiceID, req.Type); err != nil {
		return
	}
	return
}

func genAuthAPIAccessResp(req *proto.APIAccessReq, keyInfo *keystore.KeyInfo, ts int64, key []byte) (message string, err error) {
	var (
		jresp []byte
		resp  proto.AuthAPIAccessResp
	)

	resp.APIResp.Type = req.Type + 1
	resp.APIResp.ClientID = req.ClientID
	resp.APIResp.ServiceID = req.ServiceID
	resp.APIResp.Verifier = ts + 1 // increase ts by one for client verify server

	resp.KeyInfo = *keyInfo

	if jresp, err = json.Marshal(resp); err != nil {
		err = fmt.Errorf("json marshal for response failed %s", err.Error())
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, key); err != nil {
		err = fmt.Errorf("encdoe message for response failed %s", err.Error())
		return
	}

	return
}

func extractTicket(str string, key []byte) (ticket cryptoutil.Ticket, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = cryptoutil.DecodeMessage(str, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &ticket); err != nil {
		return
	}

	return
}

func checkTicketCaps(ticket *cryptoutil.Ticket, kind string, cap string) (err error) {
	c := new(caps.Caps)
	if err = c.Init(ticket.Caps); err != nil {
		return
	}
	if b := c.ContainCaps(kind, cap); !b {
		err = fmt.Errorf("no permission to access api")
		return
	}
	return
}

func verifyAPIAccessReqCommon(req *proto.APIAccessReq, tp string, resource string) (ticket cryptoutil.Ticket, ts int64, err error) {
	var (
		masterKey []byte
	)

	if err = proto.IsValidClientID(req.ClientID); err != nil {
		return
	}

	if err = proto.IsValidServiceID(req.ServiceID); err != nil {
		return
	}

	if err = proto.IsValidMsgReqType(req.ServiceID, req.Type); err != nil {
		return
	}

	masterKey = keystore.AuthMasterKey

	if ticket, err = extractTicket(req.Ticket, masterKey); err != nil {
		return
	}

	if ts, err = parseVerifier(req.Verifier, ticket.SessionKey.Key); err != nil {
		return
	}

	if err = checkTicketCaps(&ticket, tp, resource); err != nil {
		return
	}

	return
}

func newSuccessHTTPAuthReply(data interface{}) *proto.HTTPAuthReply {
	return &proto.HTTPAuthReply{Code: proto.ErrCodeSuccess, Msg: proto.ErrSuc.Error(), Data: data}
}

func sendOkReply(w http.ResponseWriter, r *http.Request, HTTPAuthReply *proto.HTTPAuthReply) (err error) {
	reply, err := json.Marshal(HTTPAuthReply)
	if err != nil {
		log.LogErrorf("fail to marshal http reply[%v]. URL[%v],remoteAddr[%v] err:[%v]", HTTPAuthReply, r.URL, r.RemoteAddr, err)
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

func keyNotFound(name string) (err error) {
	return errors.NewErrorf("parameter %v not found", name)
}

func sendErrReply(w http.ResponseWriter, r *http.Request, HTTPAuthReply *proto.HTTPAuthReply) {
	log.LogInfof("URL[%v],remoteAddr[%v],response err[%v]", r.URL, r.RemoteAddr, HTTPAuthReply)
	reply, err := json.Marshal(HTTPAuthReply)
	if err != nil {
		log.LogErrorf("fail to marshal http reply[%v]. URL[%v],remoteAddr[%v] err:[%v]", HTTPAuthReply, r.URL, r.RemoteAddr, err)
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
