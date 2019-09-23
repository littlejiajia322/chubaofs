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

func genClientGetTicketAuthResponse(req *proto.MsgAuthGetTicketReq, ts int64, r *http.Request) (message string, err error) {
	var (
		jticket   []byte
		jresp     []byte
		resp      proto.MsgAuthGetTicketResp
		masterKey []byte
		caps      []byte
	)

	resp.Type = proto.ServiceID2MsgRespMap[req.ServiceID]
	resp.ClientID = req.ClientID
	resp.ServiceID = req.ServiceID
	resp.IP = iputil.RealIP(r)
	// increase ts by one for client verify server
	resp.Verifier = ts + 1
	if caps, err = keystore.RetrieveUserCapability(resp.ClientID); err != nil {
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
		if masterKey, err = keystore.RetrieveUserMasterKey(resp.ServiceID); err != nil {
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
	if masterKey, err = keystore.RetrieveUserMasterKey(resp.ClientID); err != nil {
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

func validateReqServiceIDMsgType(serviceID string, tp proto.MsgType) (err error) {
	if !proto.IsValidServiceID(serviceID) {
		err = fmt.Errorf("invalid service ID")
		return
	}

	if !proto.IsValidMsgReqType(serviceID, tp) {
		err = fmt.Errorf("invalid request id and type")
		return
	}
	return
}

func genClientAddUserResponse(req *proto.MsgAuthCreateUserReq, ts int64, key []byte, r *http.Request) (message string, err error) {
	var (
		jresp []byte
		resp  proto.MsgAuthCreateUserResp
	)

	//resp.Type =
	resp.ApiResp.ClientID = req.ApiReq.ClientID
	resp.ApiResp.ServiceID = req.ApiReq.ServiceID
	// increase ts by one for client verify server
	resp.ApiResp.Verifier = ts + 1
	resp.UserInfo = req.UserInfo

	if jresp, err = json.Marshal(resp); err != nil {
		return
	}

	if message, err = cryptoutil.EncodeMessage(jresp, key); err != nil {
		return
	}

	return
}

func (m *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.MsgAuthGetTicketReq
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

	// TODO: check db
	if userInfo, err = keystore.RetrieveUserInfo(jobj.ClientID); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if ts, err = parseVerifier(jobj.Verifier, userInfo.Key); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if err = validateReqServiceIDMsgType(jobj.ServiceID, jobj.Type); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	// TODO check whether jobj.ip == the IP from HTTP request
	if message, err = genClientGetTicketAuthResponse(&jobj, ts, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))
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

func checkTicketCapacity(ticket *cryptoutil.Ticket, kind string, cap string) (b bool, err error) {
	c := new(caps.Caps)
	if err = c.Init(ticket.Caps); err != nil {
		return
	}
	b = c.ContainCaps(kind, cap)
	return
}

// TODO string->[]byte; error message; ticket new file
func (m *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var (
		plaintext []byte
		err       error
		jobj      proto.MsgAuthCreateUserReq
		ts        int64
		ticket    cryptoutil.Ticket
		b         bool
		//userInfo  keystore.UserInfo
		message   string
		masterKey []byte
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

	// TODO: check ServiceID == AuthMasterService
	if err = validateReqServiceIDMsgType(jobj.ApiReq.ServiceID, jobj.ApiReq.Type); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Println("Successfully validateReqServiceIDMsgType")

	masterKey = keystore.AuthMasterKey

	if ticket, err = extractTicket(jobj.ApiReq.Ticket, masterKey); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Println("Successfully extractTicket")

	// should use session key
	if ts, err = parseVerifier(jobj.ApiReq.Verifier, ticket.SessionKey.Key); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Println("Successfully parseVerifier")

	if b, err = checkTicketCapacity(&ticket, "API", "createuser"); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	fmt.Println("Successfully checkTicketCapacity")

	if b == false {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: "no permission to access api"})
		return
	}

	if jobj.UserInfo, err = keystore.AddNewUser(jobj.UserInfo.UserName, &jobj.UserInfo); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	if message, err = genClientAddUserResponse(&jobj, ts, ticket.SessionKey.Key, r); err != nil {
		sendErrReply(w, r, &proto.HTTPAuthReply{Code: proto.ErrCodeParamError, Msg: err.Error()})
		return
	}

	sendOkReply(w, r, newSuccessHTTPAuthReply(message))

	return
}

func newSuccessHTTPAuthReply(data interface{}) *proto.HTTPAuthReply {
	return &proto.HTTPAuthReply{Code: proto.ErrCodeSuccess, Msg: proto.ErrSuc.Error(), Data: data}
}

func sendOkReply(w http.ResponseWriter, r *http.Request, HTTPAuthReply *proto.HTTPAuthReply) (err error) {
	/*switch HTTPAuthReply.Data.(type) {
	case *DataPartition:
		dp := HTTPAuthReply.Data.(*DataPartition)Block
		dp.RLock()
		defer dp.RUnlock()
	case *MetaPartition:
		mp := HTTPAuthReply.Data.(*MetaPartition)
		mp.RLock()
		defer mp.RUnlock()
	case *MetaNode:
		mn := HTTPAuthReply.Data.(*MetaNode)
		mn.RLock()
		defer mn.RUnlock()
	case *DataNode:
		dn := HTTPAuthReply.Data.(*DataNode)
		dn.RLock()
		defer dn.RUnlock()
	}*/
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
