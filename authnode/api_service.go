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
		key       []byte
		message   string
	)

	if plaintext, err = m.extractClientReqInfo(r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if err = json.Unmarshal([]byte(plaintext), &jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if key, err = m.getMasterKey(jobj.ClientID); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if ts, err = parseVerifier(jobj.Verifier, key); err != nil {
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
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))
	return
}

func (m *Server) raftNodeOp(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.AuthRaftNodeReq
		ticket    cryptoutil.Ticket
		ts        int64
		message   string
	)

	if plaintext, err = m.extractClientReqInfo(r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if err = json.Unmarshal([]byte(plaintext), &jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "Unmarshal AuthRaftNodeReq failed: " + err.Error()})
		return
	}

	apiReq := jobj.APIReq
	raftNodeInfo := jobj.RaftNodeInfo

	if ticket, ts, err = m.verifyAPIAccessReqCommon(&apiReq, m.cluster.AuthServiceKey); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "verify API Access req common failed: " + err.Error()})
		return
	}

	switch apiReq.Type {
	case proto.MsgAuthAddRaftNodeReq:
		err = m.handleAddRaftNode(&raftNodeInfo)
	case proto.MsgAuthRemoveRaftNodeReq:
		err = m.handleRemoveRaftNode(&raftNodeInfo)
	default:
	}

	if err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeAuthKeyStoreError, Msg: err.Error()})
		return
	}

	msg := fmt.Sprintf("add raft node id :%v, addr:%v successfully \n", raftNodeInfo.ID, raftNodeInfo.Addr)

	if message, err = genAuthRaftNodeOpResp(&apiReq, ts, ticket.SessionKey.Key, msg); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeAuthRaftNodeGenRespError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))
	return
}

func (m *Server) handleAddRaftNode(raftNodeInfo *proto.AuthRaftNodeInfo) (err error) {
	if err = m.cluster.addRaftNode(raftNodeInfo.ID, raftNodeInfo.Addr); err != nil {
		return
	}
	return
}

func (m *Server) handleRemoveRaftNode(raftNodeInfo *proto.AuthRaftNodeInfo) (err error) {
	if err = m.cluster.removeRaftNode(raftNodeInfo.ID, raftNodeInfo.Addr); err != nil {
		return
	}
	return
}

func genAuthRaftNodeOpResp(req *proto.APIAccessReq, ts int64, key []byte, msg string) (message string, err error) {
	var (
		jresp []byte
		resp  proto.AuthRaftNodeResp
	)

	resp.APIResp.Type = req.Type + 1
	resp.APIResp.ClientID = req.ClientID
	resp.APIResp.ServiceID = req.ServiceID
	resp.APIResp.Verifier = ts + 1 // increase ts by one for client verify server

	resp.Msg = msg

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

	if err = json.Unmarshal([]byte(plaintext), &jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "Unmarshal AuthAPIAccessReq failed: " + err.Error()})
		return
	}

	apiReq := jobj.APIReq
	keyInfo := jobj.KeyInfo

	if err = keyInfo.IsValidID(); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	switch apiReq.Type {
	case proto.MsgAuthCreateKeyReq:
		if err = keyInfo.IsValidKeyInfo(); err != nil {
			sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
			return
		}
	case proto.MsgAuthDeleteKeyReq:
	case proto.MsgAuthGetKeyReq:
	case proto.MsgAuthAddCapsReq:
		fallthrough
	case proto.MsgAuthDeleteCapsReq:
		if err = keyInfo.IsValidCaps(); err != nil {
			sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
			return
		}
	default:
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: fmt.Errorf("invalid request messge type %x", int32(apiReq.Type)).Error()})
		return
	}

	if ticket, ts, err = m.verifyAPIAccessReqCommon(&apiReq, m.cluster.AuthServiceKey); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "verify API Access req common failed: " + err.Error()})
		return
	}

	switch apiReq.Type {
	case proto.MsgAuthCreateKeyReq:
		newKeyInfo, err = m.handleCreateKey(&keyInfo)
	case proto.MsgAuthDeleteKeyReq:
		newKeyInfo, err = m.handleDeleteKey(&keyInfo)
	case proto.MsgAuthGetKeyReq:
		newKeyInfo, err = m.handleGetKey(&keyInfo)
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
	return
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
	if res, err = m.getMasterKeyInfo(keyInfo.ID); err != nil {
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
	ticket.Exp = currentTime + TicketAge
	ticket.IP = IP
	ticket.Caps = caps
	return
}

func (m *Server) getMasterKey(id string) (key []byte, err error) {
	var (
		keyInfo *keystore.KeyInfo
	)
	if keyInfo, err = m.getMasterKeyInfo(id); err != nil {
		return
	}
	return keyInfo.Key, err
}

func (m *Server) getMasterKeyInfo(id string) (keyInfo *keystore.KeyInfo, err error) {
	if id == proto.AuthServiceID {
		keyInfo = &keystore.KeyInfo{
			Key:  m.cluster.AuthServiceKey,
			Caps: []byte(`{"API": ["*:*:*"]}`),
		}
	} else {
		if keyInfo, err = m.cluster.GetKey(id); err != nil {
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
		keyInfo    *keystore.KeyInfo
	)

	resp.Type = req.Type + 1
	resp.ClientID = req.ClientID
	resp.ServiceID = req.ServiceID
	// increase ts by one for client verify server
	resp.Verifier = ts + 1

	if keyInfo, err = m.getMasterKeyInfo(resp.ClientID); err != nil {
		return
	}
	caps = keyInfo.Caps

	// Use service key to encrypt ticket
	if serviceKey, err = m.getMasterKey(req.ServiceID); err != nil {
		return
	}

	ticket := m.genTicket(serviceKey, resp.ServiceID, iputil.RealIP(r), caps)
	resp.SessionKey = ticket.SessionKey

	if jticket, err = json.Marshal(ticket); err != nil {
		return
	}

	if resp.Ticket, err = cryptoutil.EncodeMessage(jticket, serviceKey); err != nil {
		return
	}

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	// Use client master key to encrypt response message
	if keyInfo, err = m.getMasterKeyInfo(resp.ClientID); err != nil {
		return
	}
	clientKey = keyInfo.Key
	if message, err = cryptoutil.EncodeMessage(jresp, clientKey); err != nil {
		return
	}

	return
}

func parseVerifier(verifier string, key []byte) (ts int64, err error) {
	var (
		plainttext []byte
	)

	if plainttext, err = cryptoutil.DecodeMessage(verifier, key); err != nil {
		return
	}

	ts = int64(binary.LittleEndian.Uint64(plainttext))

	if time.Now().Unix()-ts >= reqLiveLength { // mitigate replay attack
		err = fmt.Errorf("req verifier is timeout") // TODO
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

func (m *Server) verifyAPIAccessReqCommon(req *proto.APIAccessReq, key []byte) (ticket cryptoutil.Ticket, ts int64, err error) {
	if err = proto.IsValidClientID(req.ClientID); err != nil {
		err = fmt.Errorf("IsValidClientID failed: ", err.Error())
		return
	}

	if err = proto.IsValidServiceID(req.ServiceID); err != nil {
		err = fmt.Errorf("IsValidServiceID failed: " + err.Error())
		return
	}

	if err = proto.IsValidMsgReqType(req.ServiceID, req.Type); err != nil {
		err = fmt.Errorf("IsValidMsgReqType failed: " + err.Error())
		return
	}

	if ticket, err = extractTicket(req.Ticket, key); err != nil {
		err = fmt.Errorf("extractTicket failed: " + err.Error())
		return
	}

	if time.Now().Unix() >= ticket.Exp {
		err = fmt.Errorf("ticket expired")
		return
	}

	if ts, err = parseVerifier(req.Verifier, ticket.SessionKey.Key); err != nil {
		err = fmt.Errorf("parseVerifier failed: " + err.Error())
		return
	}

	if _, ok := proto.MsgType2ResourceMap[req.Type]; !ok {
		err = fmt.Errorf("MsgType2ResourceMap failed")
		return
	}

	rule := nodeType + capSeparator + proto.MsgType2ResourceMap[req.Type] + capSeparator + apiAction

	if err = checkTicketCaps(&ticket, nodeRsc, rule); err != nil {
		err = fmt.Errorf("checkTicketCaps failed: " + err.Error())
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
