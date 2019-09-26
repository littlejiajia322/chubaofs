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
		userInfo  keystore.UserInfo
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

	if userInfo, err = keystore.GetUserInfo(jobj.ClientID); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if ts, err = parseVerifier(jobj.Verifier, userInfo.Key); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if err = validateGetTicketReqFormat(&jobj); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	// TODO check whether jobj.ip == the IP from HTTP request
	if message, err = genGetTicketAuthResp(&jobj, ts, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))
	return
}

// TODO string->[]byte; error message
func (m *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.AuthCreateUserReq
		ts        int64
		ticket    cryptoutil.Ticket
		//userInfo  keystore.UserInfo
		message string
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

	fmt.Println("Successfully Unmarshal")

	if err = jobj.UserInfo.IsValidFormat(); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	// TODO: check ServiceID == AuthMasterService; pass value to pass reference
	if ticket, ts, err = verifyAPIAccessReqCommon(&jobj.APIReq, "API", "createuser"); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	if jobj.UserInfo, err = keystore.AddNewUser(jobj.UserInfo.ID, &jobj.UserInfo); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if message, err = genAddUserResp(&jobj, ts, ticket.SessionKey.Key, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))

	return
}

func (m *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.AuthDeleteUserReq
		ts        int64
		ticket    cryptoutil.Ticket
		//userInfo  keystore.UserInfo
		message string
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

	fmt.Println("Successfully Unmarshal")

	if ticket, ts, err = verifyAPIAccessReqCommon(&jobj.APIReq, "API", "deleteuser"); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	// should before keystore.DeleteUser
	if message, err = genDeleteUserResp(&jobj, ts, ticket.SessionKey.Key, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if err = keystore.DeleteUser(jobj.ID); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))

	return
}

func (m *Server) getUser(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.AuthGetUserReq
		ts        int64
		ticket    cryptoutil.Ticket
		//userInfo  keystore.UserInfo
		message string
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

	fmt.Println("Successfully Unmarshal")

	if ticket, ts, err = verifyAPIAccessReqCommon(&jobj.APIReq, "API", "deleteuser"); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	if message, err = genGetUserResp(&jobj, ts, ticket.SessionKey.Key, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))

	return
}

// addCaps
func (m *Server) addCaps(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.AuthAddCapsReq
		ts        int64
		ticket    cryptoutil.Ticket
		newCaps   []byte
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

	fmt.Println("Successfully Unmarshal")

	// TODO: check ServiceID == AuthMasterService; pass value to pass reference
	if ticket, ts, err = verifyAPIAccessReqCommon(&jobj.APIReq, "API", "addcaps"); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	if newCaps, err = keystore.AddCaps(jobj.ID, jobj.Caps); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	jobj.Caps = newCaps

	if message, err = genAddCapsResp(&jobj, ts, ticket.SessionKey.Key, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))
}

func (m *Server) deleteCaps(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.AuthDeleteCapsReq
		ts        int64
		ticket    cryptoutil.Ticket
		newCaps   []byte
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

	fmt.Println("Successfully Unmarshal")

	// TODO: check ServiceID == AuthMasterService; pass value to pass reference
	if ticket, ts, err = verifyAPIAccessReqCommon(&jobj.APIReq, "API", "deletecaps"); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	if newCaps, err = keystore.DeleteCaps(jobj.ID, jobj.Caps); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	jobj.Caps = newCaps

	if message, err = genDeleteCapsResp(&jobj, ts, ticket.SessionKey.Key, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))
}

func (m *Server) getCaps(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.AuthGetCapsReq
		ts        int64
		ticket    cryptoutil.Ticket
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

	fmt.Println("Successfully Unmarshal")

	// TODO: check ServiceID == AuthMasterService; pass value to pass reference
	if ticket, ts, err = verifyAPIAccessReqCommon(&jobj.APIReq, "API", "getcaps"); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	if message, err = genGetCapsResp(&jobj, ts, ticket.SessionKey.Key, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))
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

func genTicket(serviceID string, IP string, caps []byte) (ticket cryptoutil.Ticket) {
	currentTime := time.Now().Unix()
	ticket.Version = TicketVersion
	ticket.ServiceID = serviceID
	ticket.SessionKey.Ctime = currentTime
	ticket.SessionKey.Key = cryptoutil.AuthGenSessionKeyTS([]byte(keystore.AuthMasterKey))
	ticket.Exp = currentTime + TicketDuration
	ticket.IP = IP
	ticket.Caps = caps
	return
}

func genGetTicketAuthResp(req *proto.AuthGetTicketReq, ts int64, r *http.Request) (message string, err error) {
	var (
		jticket   []byte
		jresp     []byte
		resp      proto.AuthGetTicketResp
		masterKey []byte
		caps      []byte
	)

	resp.Type = proto.ServiceID2MsgRespMap[req.ServiceID]
	resp.ClientID = req.ClientID
	resp.ServiceID = req.ServiceID
	resp.IP = iputil.RealIP(r)
	// increase ts by one for client verify server
	resp.Verifier = ts + 1
	if caps, err = keystore.GetCaps(resp.ClientID); err != nil {
		return
	}
	ticket := genTicket(resp.ServiceID, resp.IP, caps)
	resp.SessionKey = ticket.SessionKey

	if jticket, err = json.Marshal(ticket); err != nil {
		return
	}
	// Use service key to encrypt ticket
	if resp.ServiceID == proto.AuthServiceID {
		masterKey = keystore.AuthMasterKey
	} else {
		if masterKey, err = keystore.GetMasterKey(resp.ServiceID); err != nil {
			return
		}
	}

	fmt.Printf("serviceID=%s serviceName=%s key=%d\n", resp.ServiceID, resp.ServiceID, len(masterKey))

	if resp.Ticket, err = cryptoutil.EncodeMessage(jticket, masterKey); err != nil {
		return
	}

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	// Use client key to encrypt response message
	if masterKey, err = keystore.GetMasterKey(resp.ClientID); err != nil {
		return
	}
	if message, err = cryptoutil.EncodeMessage(jresp, masterKey); err != nil {
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

func genAPIAccessResp(req *proto.APIAccessReq, ts int64, key []byte) (resp proto.APIAccessResp) {
	resp.Type = req.Type + 1
	resp.ClientID = req.ClientID
	resp.ServiceID = req.ServiceID
	// increase ts by one for client verify server
	resp.Verifier = ts + 1
	return
}

func genAddUserResp(req *proto.AuthCreateUserReq, ts int64, key []byte, r *http.Request) (message string, err error) {
	var (
		jresp []byte
		resp  proto.AuthCreateUserResp
	)

	resp.APIResp = genAPIAccessResp(&req.APIReq, ts, key)
	resp.UserInfo = req.UserInfo

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, key); err != nil {
		return
	}

	return
}

func genDeleteUserResp(req *proto.AuthDeleteUserReq, ts int64, key []byte, r *http.Request) (message string, err error) {
	var (
		jresp []byte
		resp  proto.AuthDeleteUserResp
	)

	resp.APIResp = genAPIAccessResp(&req.APIReq, ts, key)

	if resp.UserInfo, err = keystore.GetUserInfo(req.ID); err != nil {
		return
	}

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, key); err != nil {
		return
	}

	return
}

func genGetUserResp(req *proto.AuthGetUserReq, ts int64, key []byte, r *http.Request) (message string, err error) {
	var (
		jresp []byte
		resp  proto.AuthGetUserResp
	)

	resp.APIResp = genAPIAccessResp(&req.APIReq, ts, key)

	if resp.UserInfo, err = keystore.GetUserInfo(req.ID); err != nil {
		return
	}

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, key); err != nil {
		return
	}

	return
}

func genAddCapsResp(req *proto.AuthAddCapsReq, ts int64, key []byte, r *http.Request) (message string, err error) {
	var (
		jresp []byte
		resp  proto.AuthAddCapsResp
	)

	resp.APIResp = genAPIAccessResp(&req.APIReq, ts, key)
	resp.Caps = req.Caps

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, key); err != nil {
		return
	}

	return
}

func genDeleteCapsResp(req *proto.AuthDeleteCapsReq, ts int64, key []byte, r *http.Request) (message string, err error) {
	var (
		jresp []byte
		resp  proto.AuthDeleteCapsResp
	)

	resp.APIResp = genAPIAccessResp(&req.APIReq, ts, key)
	resp.Caps = req.Caps

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, key); err != nil {
		return
	}

	return
}

func genGetCapsResp(req *proto.AuthGetCapsReq, ts int64, key []byte, r *http.Request) (message string, err error) {
	var (
		jresp []byte
		resp  proto.AuthGetCapsResp
	)

	resp.APIResp = genAPIAccessResp(&req.APIReq, ts, key)

	if resp.Caps, err = keystore.GetCaps(req.ID); err != nil {
		return
	}

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, key); err != nil {
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
	fmt.Printf("+++++%s %s %s\n", string(ticket.Caps), kind, cap)
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
