package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
	"unsafe"

	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/keystore"
	//"github.com/chubaofs/chubaofs/authnode"
)

func genVerifier(key []byte) (v string, err error) {

	ts := time.Now().Unix()
	// encode ts for client
	tsbuf := make([]byte, unsafe.Sizeof(ts))
	binary.LittleEndian.PutUint64(tsbuf, uint64(ts))
	if v, err = cryptoutil.EncodeMessage(tsbuf, []byte(key)); err != nil {
		panic(err)
	}
	fmt.Printf("genVerifier %s\n", v)
	return
}

func getTicketFromAuth(msgType proto.MsgType, clientID string, serviceID string) (ticketStr string, key []byte) {
	var (
		err         error
		messageJSON []byte
		message     string
		msgResp     proto.AuthGetTicketResp
		ticketArray []byte
		ticket      cryptoutil.Ticket
		masterKey   []byte
	)

	// construct request body
	messageStruct := proto.AuthGetTicketReq{Type: msgType, ClientID: clientID, ServiceID: serviceID, Verifier: ""}
	if masterKey, err = keystore.RetrieveUserMasterKey(clientID); err != nil {
		panic(err)
	}

	if messageStruct.Verifier, err = genVerifier(masterKey); err != nil {
		panic(err)
	}

	if messageJSON, err = json.Marshal(messageStruct); err != nil {
		panic(err)
	}

	fmt.Printf(string(messageJSON) + "\n")

	message = base64.StdEncoding.EncodeToString(messageJSON)

	// We can use POST form to get result, too.
	resp, err := http.PostForm("http://localhost:8081/client/getticket",
		url.Values{"Message": {message}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		panic(err2)
	}
	//fmt.Printf("\nrespose: %s\n", body)

	if masterKey, err = keystore.RetrieveUserMasterKey(clientID); err != nil {
		panic(err)
	}

	if msgResp, err = proto.ParseAuthGetTicketResp(body, masterKey); err != nil {
		panic(err)
	}

	if ticketArray, err = cryptoutil.DecodeMessage(msgResp.Ticket, keystore.AuthMasterKey); err != nil {
		panic(err)
	}

	if err = json.Unmarshal(ticketArray, &ticket); err != nil {
		panic(err)
	}

	if bytes.Compare(msgResp.SessionKey.Key, ticket.SessionKey.Key) != 0 {
		panic(fmt.Errorf("session keys are not equal"))
	}

	ticketStr = msgResp.Ticket
	key = msgResp.SessionKey.Key

	return
}

func testAuthGetTicket() {
	getTicketFromAuth(proto.MsgAuthTicketReq, "admin", proto.AuthServiceID)
}

func testAuthAddUser(uid string, role string, caps []byte) {
	var (
		messageJSON []byte
		err         error
		msgResp     proto.AuthCreateUserResp
		//masterKey   []byte
	)

	clientID := "admin"
	ticket, sessionKey := getTicketFromAuth(proto.MsgAuthTicketReq, clientID, proto.AuthServiceID)

	req := proto.AuthCreateUserReq{}
	req.APIReq.Type = proto.MsgAuthCreateUserReq
	req.APIReq.ClientID = clientID
	req.APIReq.ServiceID = proto.AuthServiceID

	if req.APIReq.Verifier, err = genVerifier(sessionKey); err != nil {
		panic(err)
	}
	req.APIReq.Ticket = ticket

	req.UserInfo = keystore.UserInfo{ID: uid, Key: []byte(""), Role: role, Caps: caps}

	if messageJSON, err = json.Marshal(req); err != nil {
		panic(err)
	}
	fmt.Printf(string(messageJSON) + "\n")

	message := base64.StdEncoding.EncodeToString(messageJSON)

	// We can use POST form to get result, too.
	resp, err := http.PostForm("http://localhost:8081/admin/createuser",
		url.Values{"Message": {message}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		panic(err2)
	}
	fmt.Printf("\nrespose: %s\n", body)

	if msgResp, err = proto.ParseAuthCreateUserResp(body, sessionKey); err != nil {
		panic(err)
	}

	msgResp.UserInfo.Dump()

	return
}

func testAuthAddCaps(uid string, caps []byte) {
	var (
		err         error
		messageJSON []byte
		msgResp     proto.AuthAddCapsResp
	)
	clientID := "admin"
	ticket, sessionKey := getTicketFromAuth(proto.MsgAuthTicketReq, clientID, proto.AuthServiceID)

	req := proto.AuthAddCapsReq{}
	req.APIReq.Type = proto.MsgAuthAddCapsReq
	req.APIReq.ClientID = clientID
	req.APIReq.ServiceID = proto.AuthServiceID

	if req.APIReq.Verifier, err = genVerifier(sessionKey); err != nil {
		panic(err)
	}

	req.APIReq.Ticket = ticket

	req.ID = uid
	req.Caps = caps

	if messageJSON, err = json.Marshal(req); err != nil {
		panic(err)
	}
	fmt.Printf(string(messageJSON) + "\n")

	message := base64.StdEncoding.EncodeToString(messageJSON)

	// We can use POST form to get result, too.
	resp, err := http.PostForm("http://localhost:8081/admin/addcaps",
		url.Values{"Message": {message}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		panic(err2)
	}
	fmt.Printf("\nrespose: %s\n", body)

	if msgResp, err = proto.ParseAuthAddCapsResp(body, sessionKey); err != nil {
		panic(err)
	}

	fmt.Printf("new caps: %s\n", string(msgResp.Caps))

}

func main() {

	fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	testAuthGetTicket()
	fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	testAuthAddUser("zeng", "client", []byte(`{"API":["mount"]}`))
	fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	testAuthAddCaps("zeng", []byte(`{"API":["open"]}`))
	fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	testAuthAddCaps("zeng", []byte(`{"API":["open"]}`))
	fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	testAuthAddCaps("zeng", []byte(`{"API":["*"]}`))

	return
}
