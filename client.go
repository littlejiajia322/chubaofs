package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	//"github.com/chubaofs/chubaofs/authnode"
)

func main() {
	var (
		err         error
		messageJSON []byte
		message     string
		msgResp     proto.MsgClientGetTicketAuthResp
		ticket_array []byte
		ticket proto.Ticket
	)
	clientID := "client1"
	serviceID := proto.MasterServiceID
	ts := time.Now().Unix()
	// construct request body
	messageStruct := proto.MsgClientGetTicketAuthReq{Type: proto.MsgMasterTicketReq, ClientID: clientID, ServiceID: serviceID, Ts: ts}
	var messageStruct2 proto.MsgClientGetTicketAuthReq
	if messageJSON, err = json.Marshal(messageStruct); err != nil {
		panic(err)
	}
	fmt.Printf(string(messageJSON) + "\n")

	if err = json.Unmarshal(messageJSON, &messageStruct2); err != nil {
		panic(err)
	}
	fmt.Printf("%s %d \n", messageStruct2.ClientID, messageStruct2.ServiceID)

	// encrption
	message, err = cryptoutil.EncodeMessage(messageJSON, []byte("11111111111111111111111111111111"))
	if err != nil {
		panic(err)
	}

	fmt.Printf(string(messageJSON))

	// We can use POST form to get result, too.
	resp, err := http.PostForm("http://localhost:8081/client/getticket",
		url.Values{"ClientID": {"client1"}, "Message": {message}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		panic(err2)
	}
	fmt.Printf("\nrespose: %s\n", body)

	if msgResp, err = proto.ParseAuthTicketReply(body, []byte("11111111111111111111111111111111")); err != nil {
		panic(err)
	}

	if ticket_array, err = cryptoutil.DecodeMessage(msgResp.Ticket, []byte("22222222222222222222222222222222")); err != nil {
		panic(err)
	}

	if err = json.Unmarshal(ticket_array, &ticket); err != nil {
		panic(err)
	}

	fmt.Printf("ticket %v", ticket)

	return
}
