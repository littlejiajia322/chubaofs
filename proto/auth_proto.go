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
	AdminAddCaps    = "/admin/addcaps"

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
	// MsgAuthTicketReq request type for an auth ticket
	MsgAuthTicketReq MsgType = 0x10000

	// MsgAuthTicketResp respose type for an auth ticket
	MsgAuthTicketResp MsgType = 0x10001

	// MsgMasterTicketReq request type for a master ticket
	MsgMasterTicketReq MsgType = 0x20000

	// MsgMasterTicketResp response type for a master ticket
	MsgMasterTicketResp MsgType = 0x20001

	// MsgMetaTicketReq request type for a metanode ticket
	MsgMetaTicketReq MsgType = 0x30000

	// MsgMetaTicketResp response type for a metanode ticket
	MsgMetaTicketResp MsgType = 0x30001

	// MsgDataTicketReq request type for a datanode ticket
	MsgDataTicketReq MsgType = 0x40000

	// MsgDataTicketResp response type for a datanode ticket
	MsgDataTicketResp MsgType = 0x40001

	// MsgAuthAPIAccessReq request type for authnode api access
	MsgAuthAPIAccessReq MsgType = 0x50000

	// MsgAuthAPIAccessResp response type for authnode api access
	MsgAuthAPIAccessResp MsgType = 0x50001

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

// MsgReq2ServiceIDMap map serviceID to Auth msg request
var MsgReq2ServiceIDMap = map[MsgType]string{
	MsgAuthTicketReq:      AuthServiceID,
	MsgMasterTicketReq:    MasterServiceID,
	MsgMetaTicketReq:      MetaServiceID,
	MsgDataTicketReq:      DataServiceID,
	MsgAuthAPIAccessReq:   AuthServiceID,
	MsgMasterAPIAccessReq: MasterServiceID,
}

// ServiceID2MsgRespMap map serviceID to Auth msg response
var ServiceID2MsgRespMap = map[string]MsgType{
	AuthServiceID:   MsgAuthTicketResp,
	MasterServiceID: MsgMasterTicketResp,
	MetaServiceID:   MsgMetaTicketResp,
	DataServiceID:   MsgDataTicketResp,
}

// ServiceID2MsgRespMap map serviceID to Auth msg response
var AuthReq2RespMap = map[MsgType]MsgType{
	MsgAuthTicketReq:      MsgAuthTicketResp,
	MsgMasterTicketReq:    MsgMasterTicketResp,
	MsgMetaTicketReq:      MsgMetaTicketResp,
	MsgDataTicketReq:      MsgDataTicketResp,
	MsgAuthAPIAccessReq:   MsgAuthAPIAccessResp,
	MsgMasterAPIAccessReq: MsgMasterAPIAccessResp,
}

// MsgClientGetTicketAuthReq defines the message from client to authnode
// use Timestamp as verifier for MITM mitigation
// verifier is also used to verify the server identity
type MsgAuthGetTicketReq struct {
	Type      MsgType `json:"type"`
	ClientID  string  `json:"client_id"`
	ServiceID string  `json:"service_id"`
	Verifier  string  `json:"verifier"`
}

// MsgClientGetTicketAuthResp defines the message from authnode to client
type MsgAuthGetTicketResp struct {
	Type       MsgType              `json:"type"`
	ClientID   string               `json:"client_id"`
	ServiceID  string               `json:"service_id"`
	IP         string               `json:"ip"`
	Verifier   int64                `json:"verifier"`
	Ticket     string               `json:"ticket"`
	SessionKey cryptoutil.CryptoKey `json:"session_key"`
}

// MsgAPIAccessReq defines the request for access restful api
// use Timestamp as verifier for MITM mitigation
// verifier is also used to verify the server identity
type MsgAPIAccessReq struct {
	Type      MsgType `json:"type"`
	ClientID  string  `json:"client_id"`
	ServiceID string  `json:"service_id"`
	Verifier  string  `json:"verifier"`
	Ticket    string  `json:"ticket"`
}

// MsgAPIAccessResp defines the respose for access restful api
// use Timestamp as verifier for MITM mitigation
// verifier is also used to verify the server identity
type MsgAPIAccessResp struct {
	Type      MsgType `json:"type"`
	ClientID  string  `json:"client_id"`
	ServiceID string  `json:"service_id"`
	Verifier  int64   `json:"verifier"`
}

// AuthMsgCreateUserReq defines the request for creating an authnode user
type MsgAuthCreateUserReq struct {
	ApiReq   MsgAPIAccessReq   `json:"api_req"`
	UserInfo keystore.UserInfo `json:"user_info"`
}

// MsgAuthCreateUserResp defines the respose for creating an user in authnode
type MsgAuthCreateUserResp struct {
	ApiResp  MsgAPIAccessResp  `json:"api_resp"`
	UserInfo keystore.UserInfo `json:"user_info"`
}

// MsgAuthDeleteUserReq defines the request for deleting an authnode user
type MsgAuthDeleteUserReq struct {
	ApiReq   MsgAPIAccessReq `json:"api_req"`
	ClientID string          `json:"id"`
}

// MsgAuthAddCapsReq defines the message for adding caps for a user in authnode
type MsgAuthAddCapsReq struct {
	ApiReq MsgAPIAccessReq `json:"apiReq"`
	ID     string          `json:"id"`
	Caps   []byte          `json:"caps"`
}

// MsgAuthAddCapsResp defines the message for adding caps for a user in authnode
type MsgAuthAddCapsResp struct {
	ApiResp MsgAPIAccessResp `json:"apiReq"`
	Caps    []byte           `json:"caps"`
}

// MsgAuthAddCapsReq defines the message for adding caps for an user in authnode
type MsgAuthDeleteCapsReq struct {
	ApiReq MsgAPIAccessReq `json:"apiReq"`
	Caps   []byte          `json:"caps"`
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
	if MsgReq2ServiceIDMap[msgType] != serviceID {
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

func getPlaintextFromResp(body []byte, key []byte) (plaintext []byte, err error) {
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
func ParseAuthGetTicketResp(body []byte, key []byte) (resp MsgAuthGetTicketResp, err error) {
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

// ParseAuthCreateUserResp parse and validate the auth create user resp
func ParseAuthCreateUserResp(body []byte, key []byte) (resp MsgAuthCreateUserResp, err error) {
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
