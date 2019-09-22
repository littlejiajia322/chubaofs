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

func genVerifier(key string) (v string) {
	var (
		err error
	)
	ts := time.Now().Unix()
	// encode ts for client
	tsbuf := make([]byte, unsafe.Sizeof(ts))
	binary.LittleEndian.PutUint64(tsbuf, uint64(ts))
	if v, err = cryptoutil.EncodeMessage(tsbuf, []byte(key)); err != nil {
		panic(err)
	}
	return
}

func testAuthGetTicket() {
	var (
		err          error
		messageJSON  []byte
		message      string
		msgResp      proto.MsgClientGetTicketAuthResp
		ticket_array []byte
		ticket       proto.Ticket
	)
	clientID := "admin"
	serviceID := proto.MasterServiceID
	
	// construct request body
	messageStruct := proto.MsgClientGetTicketAuthReq{Type: proto.MsgMasterTicketReq, ClientID: clientID, ServiceID: serviceID, Verifier: ""}


	messageStruct.Verifier = genVerifier("33333333333333333333333333333333")
	//var messageStruct2 proto.MsgClientGetTicketAuthReq
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
	fmt.Printf("\nrespose: %s\n", body)

	if msgResp, err = proto.ParseAuthTicketReply(body, []byte("33333333333333333333333333333333")); err != nil {
		panic(err)
	}

	if ticket_array, err = cryptoutil.DecodeMessage(msgResp.Ticket, []byte("22222222222222222222222222222222")); err != nil {
		panic(err)
	}

	if err = json.Unmarshal(ticket_array, &ticket); err != nil {
		panic(err)
	}

	if bytes.Compare(msgResp.SessionKey.Key, ticket.SessionKey.Key) != 0 {
		panic(fmt.Errorf("session keys are not equal"))
	}
	
	testAddUser(msgResp.Ticket)
}

func testAddUser(ticket string) {
	var (
		messageJSON []byte
		err error
	)
	req := proto.MsgAuthCreateUserReq{}
	req.ApiReq.Type = proto.MsgAuthAPIAccessReq
	req.ApiReq.ClientID = "12345"
	req.ApiReq.ServiceID = proto.AuthServiceID
	req.ApiReq.Verifier = genVerifier("33333333333333333333333333333333")
	req.ApiReq.Ticket = ticket

	req.UserInfo = keystore.UserInfo{UserName:"zeng", Key:"12345", Role:"Client", Caps:[]byte("")}
	
	
	if messageJSON, err = json.Marshal(req); err != nil {
		panic(err)
	}
	fmt.Printf(string(messageJSON) + "\n")
	
	message := base64.StdEncoding.EncodeToString(messageJSON)

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
	fmt.Printf("\nrespose: %s\n", body)

	
}

func main() {

	testAuthGetTicket()
	

	return
}
