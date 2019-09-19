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
)


func main() {
	var (
		err          error
		messageJSON []byte
		message      string
	)
	clientID := "client1"
<<<<<<< HEAD
	serviceID := proto.MasterServiceID
=======
	serviceID := proto.MasterService
>>>>>>> f36b2d718c3762264feb77add437d8f65a036bf6
	ip := "123456789"
	ts := time.Now().Unix()
	// construct request body
	messageStruct := proto.MsgClientAuthReq{Type: proto.MsgMasterTicketReq, ClientID: clientID, ServiceID: serviceID, IP: ip, Ts: ts}
	var messageStruct2 proto.MsgClientAuthReq
	if messageJSON, err = json.Marshal(messageStruct); err != nil {
		panic(err)
	}
	fmt.Printf(string(messageJSON) + "\n")

	if err = json.Unmarshal(messageJSON, &messageStruct2); err != nil {
		panic(err)
	}
	fmt.Printf("%s %s %d \n", messageStruct2.ClientID, messageStruct2.IP, messageStruct2.ServiceID)

	// encrption
	message, err = cryptoutil.EncodeMessage(messageJSON, []byte("11111111111111111111111111111111"))
	if err != nil {
		panic(err)
	}

	if messageJSON, err = cryptoutil.DecodeMessage(message, []byte("11111111111111111111111111111111")); err != nil {
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
	//fmt.Println("post:\n", keepLines(string(body), 3))
	fmt.Printf("respose: %s", string(body))

	return
}
