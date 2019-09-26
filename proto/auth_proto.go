// Copyright 2018 The Chubao Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package proto

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/keystore"
)

// ServiceID defines the type of tickets
type ServiceID uint32

// MsgType defines the type of req/resp for message
type MsgType uint32

// Nonce defines the nonce to mitigate the replay attack
type Nonce uint64

// api
const (
	// Client APIs
	ClientGetTicket = "/client/getticket"

	// Admin APIs
	AdminCreateUser = "/admin/createuser"
	AdminDeleteUser = "/admin/deleteuser"
	AdminGetUser    = "/admin/getuser"
	AdminAddCaps    = "/admin/addcaps"
	AdminDeleteCaps = "/admin/deletecaps"
	AdminGetCaps    = "/admin/getcaps"

	//raft node APIs

	// Node APIs

	// Operation response

)

const (
	// AuthServiceID defines ticket for authnode access (not supported)
	AuthServiceID = "AuthService"

	// MasterServiceID defines ticket for master access
	MasterServiceID = "MasterService"

	// MetaServiceID defines ticket for metanode access (not supported)
	MetaServiceID = "MetanodeService"

	// DataServiceID defines ticket for datanode access (not supported)
	DataServiceID = "DatanodeService"
)

const (
	// MsgAuthBase define the starting value for auth message
	MsgAuthBase MsgType = 0x100000

	// MsgAuthTicketReq request type for an auth ticket
	MsgAuthTicketReq MsgType = MsgAuthBase + 0x10000

	// MsgAuthTicketResp respose type for an auth ticket
	MsgAuthTicketResp MsgType = MsgAuthBase + 0x10001

	// MsgMasterTicketReq request type for a master ticket
	MsgMasterTicketReq MsgType = MsgAuthBase + 0x20000

	// MsgMasterTicketResp response type for a master ticket
	MsgMasterTicketResp MsgType = MsgAuthBase + 0x20001

	// MsgMetaTicketReq request type for a metanode ticket
	MsgMetaTicketReq MsgType = MsgAuthBase + 0x30000

	// MsgMetaTicketResp response type for a metanode ticket
	MsgMetaTicketResp MsgType = MsgAuthBase + 0x30001

	// MsgDataTicketReq request type for a datanode ticket
	MsgDataTicketReq MsgType = MsgAuthBase + 0x40000

	// MsgDataTicketResp response type for a datanode ticket
	MsgDataTicketResp MsgType = MsgAuthBase + 0x40001

	// MsgAuthCreateUserReq request type for authnode add user
	MsgAuthCreateUserReq MsgType = MsgAuthBase + 0x51000

	// MsgAuthCreateUserResp response type for authnode add user
	MsgAuthCreateUserResp MsgType = MsgAuthBase + 0x51001

	// MsgAuthDeleteUserReq request type for authnode delete user
	MsgAuthDeleteUserReq MsgType = MsgAuthBase + 0x52000

	// MsgAuthDeleteUserResp response type for authnode delete user
	MsgAuthDeleteUserResp MsgType = MsgAuthBase + 0x52001

	// MsgAuthGetUserReq request type for authnode get user info
	MsgAuthGetUserReq MsgType = MsgAuthBase + 0x53000

	// MsgAuthGetUserResp response type for authnode get user info
	MsgAuthGetUserResp MsgType = MsgAuthBase + 0x53001

	// MsgAuthAddCapsReq request type for authnode add caps
	MsgAuthAddCapsReq MsgType = MsgAuthBase + 0x54000

	// MsgAuthAddCapsResp response type for authnode add caps
	MsgAuthAddCapsResp MsgType = MsgAuthBase + 0x54001

	// MsgAuthDeleteCapsReq request type for authnode add caps
	MsgAuthDeleteCapsReq MsgType = MsgAuthBase + 0x55000

	// MsgAuthDeleteCapsResp response type for authnode add caps
	MsgAuthDeleteCapsResp MsgType = MsgAuthBase + 0x55001

	// MsgAuthGetCapsReq request type for authnode add caps
	MsgAuthGetCapsReq MsgType = MsgAuthBase + 0x56000

	// MsgAuthGetCapsResp response type for authnode add caps
	MsgAuthGetCapsResp MsgType = MsgAuthBase + 0x56001

	// MsgMasterAPIAccessReq request type for master api access
	MsgMasterAPIAccessReq MsgType = 0x60000

	// MsgMasterAPIAccessResp response type for master api access
	MsgMasterAPIAccessResp MsgType = 0x60001
)

// HTTPAuthReply uniform response structure
type HTTPAuthReply struct {
	Code int32       `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

// ServiceID2MsgRespMap map serviceID to Auth msg response
var ServiceID2MsgRespMap = map[string]MsgType{
	AuthServiceID:   MsgAuthTicketResp,
	MasterServiceID: MsgMasterTicketResp,
	MetaServiceID:   MsgMetaTicketResp,
	DataServiceID:   MsgDataTicketResp,
}

// AuthGetTicketReq defines the message from client to authnode
// use Timestamp as verifier for MITM mitigation
// verifier is also used to verify the server identity
type AuthGetTicketReq struct {
	Type      MsgType `json:"type"`
	ClientID  string  `json:"client_id"`
	ServiceID string  `json:"service_id"`
	Verifier  string  `json:"verifier"`
}

// AuthGetTicketResp defines the message from authnode to client
type AuthGetTicketResp struct {
	Type       MsgType              `json:"type"`
	ClientID   string               `json:"client_id"`
	ServiceID  string               `json:"service_id"`
	IP         string               `json:"ip"`
	Verifier   int64                `json:"verifier"`
	Ticket     string               `json:"ticket"`
	SessionKey cryptoutil.CryptoKey `json:"session_key"`
}

// APIAccessReq defines the request for access restful api
// use Timestamp as verifier for MITM mitigation
// verifier is also used to verify the server identity
type APIAccessReq struct {
	Type      MsgType `json:"type"`
	ClientID  string  `json:"client_id"`
	ServiceID string  `json:"service_id"`
	Verifier  string  `json:"verifier"`
	Ticket    string  `json:"ticket"`
}

// APIAccessResp defines the respose for access restful api
// use Timestamp as verifier for MITM mitigation
// verifier is also used to verify the server identity
type APIAccessResp struct {
	Type      MsgType `json:"type"`
	ClientID  string  `json:"client_id"`
	ServiceID string  `json:"service_id"`
	Verifier  int64   `json:"verifier"`
}

// AuthCreateUserReq defines the request for creating an authnode user
type AuthCreateUserReq struct {
	APIReq   APIAccessReq      `json:"api_req"`
	UserInfo keystore.UserInfo `json:"user_info"`
}

// AuthCreateUserResp defines the respose for creating an user in authnode
type AuthCreateUserResp struct {
	APIResp  APIAccessResp     `json:"api_resp"`
	UserInfo keystore.UserInfo `json:"user_info"`
}

// AuthDeleteUserReq defines the request for deleting an authnode user
type AuthDeleteUserReq struct {
	APIReq APIAccessReq `json:"api_req"`
	ID     string       `json:"id"`
}

// AuthDeleteUserResp defines the response for deleting an authnode user
type AuthDeleteUserResp struct {
	APIResp  APIAccessResp     `json:"api_req"`
	UserInfo keystore.UserInfo `json:"user_info"`
}

// AuthGetUserReq defines the request for getting an authnode user
type AuthGetUserReq struct {
	APIReq APIAccessReq `json:"api_req"`
	ID     string       `json:"id"`
}

// AuthGetUserResp defines the response for getting an authnode user
type AuthGetUserResp struct {
	APIResp  APIAccessResp     `json:"api_req"`
	UserInfo keystore.UserInfo `json:"user_info"`
}

// AuthAddCapsReq defines the request for adding caps for a user in authnode
type AuthAddCapsReq struct {
	APIReq APIAccessReq `json:"apiReq"`
	ID     string       `json:"id"`
	Caps   []byte       `json:"caps"`
}

// AuthAddCapsResp defines the response for adding caps for a user in authnode
type AuthAddCapsResp struct {
	APIResp APIAccessResp `json:"apiReq"`
	Caps    []byte        `json:"caps"`
}

// AuthGetCapsReq defines the request for getting caps for a user in authnode
type AuthGetCapsReq struct {
	APIReq APIAccessReq `json:"apiReq"`
	ID     string       `json:"id"`
}

// AuthGetCapsResp defines the response for getting caps for a user in authnode
type AuthGetCapsResp struct {
	APIResp APIAccessResp `json:"apiReq"`
	Caps    []byte        `json:"caps"`
}

// AuthDeleteCapsReq defines the message for deleting caps for an user in authnode
type AuthDeleteCapsReq struct {
	APIReq APIAccessReq `json:"apiReq"`
	ID     string       `json:"id"`
	Caps   []byte       `json:"caps"`
}

// AuthDeleteCapsResp defines the message for deleting caps for an user in authnode
type AuthDeleteCapsResp struct {
	APIResp APIAccessResp `json:"apiReq"`
	ID      string        `json:"id"`
	Caps    []byte        `json:"caps"`
}

// IsValidServiceID determine the validity of a serviceID
func IsValidServiceID(serviceID string) (err error) {
	if serviceID != AuthServiceID && serviceID != MasterServiceID && serviceID != MetaServiceID && serviceID != DataServiceID {
		err = fmt.Errorf("invalid service ID [%s]", serviceID)
		return
	}
	return
}

// IsValidMsgReqType determine the validity of a message type
func IsValidMsgReqType(serviceID string, msgType MsgType) (err error) {
	b := false
	switch serviceID {
	case "AuthService":
		if msgType|MsgAuthBase != 0 {
			b = true
		}
	}
	if !b {
		err = fmt.Errorf("invalid request type [%x] and serviceID[%s]", msgType, serviceID)
		return
	}
	return
}

// IsValidClientID determine the validity of a clientID
func IsValidClientID(id string) (err error) {
	re := regexp.MustCompile("^[A-Za-z]{1,1}[A-Za-z0-9_]{0,11}$")
	if !re.MatchString(id) {
		err = fmt.Errorf("clientID invalid format [%s]", id)
		return
	}
	return
}

// GetMessageFromResp
func GetDataFromResp(body []byte, key []byte) (plaintext []byte, err error) {
	var (
		jobj HTTPAuthReply
	)
	if err = json.Unmarshal(body, &jobj); err != nil {
		return
	}

	if jobj.Code != 0 {
		err = fmt.Errorf(jobj.Msg)
		return
	}

	data := fmt.Sprint(jobj.Data)
	//fmt.Println(data)

	if plaintext, err = cryptoutil.DecodeMessage(data, key); err != nil {
		return
	}

	return
}

// ParseAuthGetTicketResp parse and validate the auth tget icket resp
func ParseAuthGetTicketResp(body []byte, key []byte) (resp AuthGetTicketResp, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = GetDataFromResp(body, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &resp); err != nil {
		return
	}

	return
}

/*
// ParseAuthCreateUserResp parse and validate the auth create user resp
func ParseAuthCreateUserResp(body []byte, key []byte) (resp AuthCreateUserResp, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = getPlaintextFromResp(body, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &resp); err != nil {
		return
	}

	return
}

// ParseAuthDeleteUserResp parse and validate the auth delete user resp
func ParseAuthDeleteUserResp(body []byte, key []byte) (resp AuthDeleteUserResp, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = getPlaintextFromResp(body, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &resp); err != nil {
		return
	}

	return
}

// ParseAuthGetUserResp parse and validate the auth get user resp
func ParseAuthGetUserResp(body []byte, key []byte) (resp AuthGetUserResp, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = getPlaintextFromResp(body, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &resp); err != nil {
		return
	}

	return
}

// ParseAuthAddCapsResp parse and validate the auth add caps resp
func ParseAuthAddCapsResp(body []byte, key []byte) (resp AuthAddCapsResp, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = getPlaintextFromResp(body, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &resp); err != nil {
		return
	}

	return
}

// ParseAuthDeleteCapsResp parse and validate the auth delete caps resp
func ParseAuthDeleteCapsResp(body []byte, key []byte) (resp AuthDeleteCapsResp, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = getPlaintextFromResp(body, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &resp); err != nil {
		return
	}

	return
}

// ParseAuthGetCapsResp parse and validate the auth get caps resp
func ParseAuthGetCapsResp(body []byte, key []byte) (resp AuthGetCapsResp, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = getPlaintextFromResp(body, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &resp); err != nil {
		return
	}

	return
}

func ParseAuthResp(body []byte, key []byte) (data interface{}, err error) {
	var (
		plaintext []byte
	)

	if plaintext, err = getMessageFromResp(body, key); err != nil {
		return
	}

	if err = json.Unmarshal(plaintext, &data); err != nil {
		return
	}

	return
}*/
