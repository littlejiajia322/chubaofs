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

	//"time"

	"github.com/chubaofs/chubaofs/util/cryptoutil"
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

	//raft node APIs

	// Node APIs

	// Operation response

)

const (
	// AuthServiceID defines ticket for authnode access (not supported)
	AuthServiceID ServiceID = 0x1000

	// MasterServiceID defines ticket for master access
	MasterServiceID ServiceID = 0x2000

	// MetaServiceID defines ticket for metanode access (not supported)
	MetaServiceID ServiceID = 0x3000

	// DataServiceID defines ticket for datanode access (not supported)
	DataServiceID ServiceID = 0x4000
)

const (
	// MsgAuthTicketReq request type for an auth ticket
	MsgAuthTicketReq MsgType = 0x10000

	// MsgAuthTicketResp respose type for an auth ticket
	MsgAuthTicketResp MsgType = 0x20000

	// MsgMasterTicketReq request type for a master ticket
	MsgMasterTicketReq MsgType = 0x30000

	// MsgMasterTicketResp response type for a master ticket
	MsgMasterTicketResp MsgType = 0x40000

	// MsgMetaTicketReq request type for a metanode ticket
	MsgMetaTicketReq MsgType = 0x50000

	// MsgMetaTicketResp response type for a metanode ticket
	MsgMetaTicketResp MsgType = 0x60000

	// MsgDataTicketReq request type for a datanode ticket
	MsgDataTicketReq MsgType = 0x70000

	// MsgDataTicketResp response type for a datanode ticket
	MsgDataTicketResp MsgType = 0x80000
)

// HTTPGetTicketAuthReply uniform response structure
type HTTPGetTicketAuthReply struct {
	Code int32       `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

// ServiceID2MsgReqMap map serviceID to Auth msg request
var ServiceID2MsgReqMap = map[ServiceID]MsgType{
	AuthServiceID:   MsgAuthTicketReq,
	MasterServiceID: MsgMasterTicketReq,
	MetaServiceID:   MsgMetaTicketReq,
	DataServiceID:   MsgDataTicketReq,
}

// ServiceID2MsgRespMap map serviceID to Auth msg response
var ServiceID2MsgRespMap = map[ServiceID]MsgType{
	AuthServiceID:   MsgAuthTicketResp,
	MasterServiceID: MsgMasterTicketResp,
	MetaServiceID:   MsgMetaTicketResp,
	DataServiceID:   MsgDataTicketResp,
}

// ServiceID2NameMap map serviceID to Auth msg response
var ServiceID2NameMap = map[ServiceID]string{
	AuthServiceID:   "AuthService",
	MasterServiceID: "MasterService",
	MetaServiceID:   "MetaService",
	DataServiceID:   "DataService",
}

// ServiceName2IDMap map serviceID to Auth msg response
var ServiceName2IDMap = map[string]ServiceID{
	"AuthService":   AuthServiceID,
	"MasterService": MasterServiceID,
	"MetaService":   MetaServiceID,
	"DataService":   DataServiceID,
}

/*
* MITM thread:
*      (1) talking to the right party (nonce, key encryption)
*      (2) replay attack (IP, timestamp constrains)
*
* Other thread: Client capability changes (ticket timestamp)
 */

// Ticket is a temperary struct to store the permission/caps for a client to
// access principle
type Ticket struct {
	Version    uint8     `json:"version"`
	ServiceID  ServiceID `json:"service_id"`
	SessionKey CryptoKey `json:"session_key"`
	Exp        int64     `json:"exp"`
	IP         string    `json:"ip"`
	Caps       []byte    `json:"caps"`
}

// CryptoKey store the session key
type CryptoKey struct {
	Ctime int64  `json:"c_time"`
	Key   []byte `json:"key"`
}

// MsgClientGetTicketAuthReq defines the message from client to authnode
type MsgClientGetTicketAuthReq struct {
	Type      MsgType   `json:"type"`
	ClientID  string    `json:"client_id"`
	ServiceID ServiceID `json:"service_id"`
	Ts        int64     `json:"ts"`
}

// MsgClientGetTicketAuthResp defines the message from authnode to client
type MsgClientGetTicketAuthResp struct {
	Type       MsgType   `json:"type"`
	ClientID   string    `json:"client_id"`
	ServiceID  ServiceID `json:"service_id"`
	IP         string    `json:"ip"`
	Ts         int64     `json:"ts"`
	Ticket     string    `json:"ticket"`
	SessionKey CryptoKey `json:"session_key"`
}

// IsValidServiceID determine the validity of a serviceID
func IsValidServiceID(serviceID ServiceID) (b bool) {
	b = (serviceID == AuthServiceID || serviceID == MasterServiceID || serviceID == MetaServiceID || serviceID == DataServiceID)
	return
}

// IsValidMsgReqType determine the validity of a message type
func IsValidMsgReqType(serviceID ServiceID, msgType MsgType) (b bool) {
	b = ServiceID2MsgReqMap[serviceID] == msgType
	return
}

// ParseAuthTicketReply parse and validate the auth ticket reply
func ParseAuthTicketReply(body []byte, key []byte) (resp MsgClientGetTicketAuthResp, err error) {
	var (
		jobj      HTTPGetTicketAuthReply
		plaintext []byte
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

	if err = json.Unmarshal(plaintext, &resp); err != nil {
		return
	}
	fmt.Printf("resp=%v\n", resp)
	return

}

/*
// HTTPReply uniform response structure
type HTTPReply struct {
	Code int32       `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

// RegisterMetaNodeResp defines the response to register a meta node.
type RegisterMetaNodeResp struct {
	ID uint64
		messageJSON2 []byte
}

// ClusterInfo defines the cluster infomation.
type ClusterInfo struct {
	Cluster string
	Ip      string
}

// CreateDataPartitionRequest defines the request to create a data partition.
type CreateDataPartitionRequest struct {
	PartitionType string
	PartitionId   uint64
	PartitionSize int
	VolumeId      string
	IsRandomWrite bool
	Members       []Peer
	Hosts         []string
	CreateType    int
}

// CreateDataPartitionResponse defines the response to the request of creating a data partition.
type CreateDataPartitionResponse struct {
	PartitionId uint64
	Status      uint8
	Result      string
}

// DeleteDataPartitionRequest defines the request to delete a data partition.
type DeleteDataPartitionRequest struct {
	DataPartitionType string
	PartitionId       uint64
	PartitionSize     int
}

// DeleteDataPartitionResponse defines the response to the request of deleting a data partition.
type DeleteDataPartitionResponse struct {
	Status      uint8
	Result      string
	PartitionId uint64
}

// DataPartitionDecommissionRequest defines the request of decommissioning a data partition.
type DataPartitionDecommissionRequest struct {
	PartitionId uint64
	RemovePeer  Peer
	AddPeer     Peer
}

// DataPartitionDecommissionResponse defines the response to the request of decommissioning a data partition.
type DataPartitionDecommissionResponse struct {
	Status      uint8
	Result      string
	PartitionId uint64
}

// LoadDataPartitionRequest defines the request of loading a data partition.
type LoadDataPartitionRequest struct {
	PartitionId uint64
}

// LoadDataPartitionResponse defines the response to the request of loading a data partition.
type LoadDataPartitionResponse struct {
	PartitionId       uint64
	Used              uint64
	PartitionSnapshot []*File
	Status            uint8
	PartitionStatus   int
	Result            string
	VolName           string
}

// File defines the file struct.
type File struct {
	Name     string
	Crc      uint32
	Size     uint32
	Modified int64resp        
}

// LoadMetaPartitionMetricRequest defines the request of loading the meta partition metrics.
type LoadMetaPartitionMetricRequest struct {
	PartitionID uint64
	Start       uint64
	End         uint64
}

// LoadMetaPartitionMetricResponse defines the response to the request of loading the meta partition metrics.
type LoadMetaPartitionMetricResponse struct {
	Start    uint64
	End      uint64
	MaxInode uint64
	Status   uint8
	Result   string
}

// HeartBeatRequest define the heartbeat request.
type HeartBeatRequest struct {
	CurrTime   int64
	MasterAddr string
}

// PartitionReport defines the partition report.
type PartitionReport struct {
	VolName         string
	PartitionID     uint64
	PartitionStatus int
	Total           uint64
	Used            uint64
	DiskPath        string
	IsLeader        bool
	ExtentCount     int
	NeedCompare     bool
}

// DataNodeHeartbeatResponse defines the response to the data node heartbeat.
type DataNodeHeartbeatResponse struct {
	Total               uint64
	Used                uint64
	Available           uint64
	TotalPartitionSize  uint64 // volCnt * volsize
	RemainingCapacity   uint64 // remaining capacity to create partition
	CreatedPartitionCnt uint32
	MaxCapacity         uint64 // maximum capacity to create partition
	RackName            string
	PartitionReports    []*PartitionReport
	Status              uint8
	Result              string
}

// MetaPartitionReport defines the meta partition report.
type MetaPartitionReport struct {
	PartitionID uint64
	Start       uint64
	End         uint64
	Status      int
	MaxInodeID  uint64
	IsLeader    bool
	VolName     string
}

// MetaNodeHeartbeatResponse defines the response to the meta node heartbeat request.
type MetaNodeHeartbeatResponse struct {
	RackName             string
	Total                uint64
	Used                 uint64
	MetaPartitionReports []*MetaPartitionReport
	Status               uint8
	Result               string
}

// DeleteFileRequest defines the request to delete a file.
type DeleteFileRequest struct {
	VolId uint64
	Name  string
}

// DeleteFileResponse defines the response to the request of deleting a file.
type DeleteFileResponse struct {
	Status uint8
	Result string
	VolId  uint64
	Name   string
}

// DeleteMetaPartitionRequest defines the request of deleting a meta partition.
type DeleteMetaPartitionRequest struct {
	PartitionID uint64
}

// DeleteMetaPartitionResponse defines the response to the request of deleting a meta partition.
type DeleteMetaPartitionResponse struct {
	PartitionID uint64
	Status      uint8
	Result      string
}

// UpdateMetaPartitionRequest defines the request to update a meta partition.
type UpdateMetaPartitionRequest struct {
	PartitionID uint64
	VolName     string
	Start       uint64
	End         uint64
}

// UpdateMetaPartitionResponse defines the response to the request of updating the meta partition.
type UpdateMetaPartitionResponse struct {
	PartitionID uint64
	VolName     string
	End         uint64
	Status      uint8
	Result      string
}

// MetaPartitionDecommissionRequest defines the request of decommissioning a meta partition.
type MetaPartitionDecommissionRequest struct {
	PartitionID uint64
	VolName     string
	RemovePeer  Peer
	AddPeer     Peer
}

// MetaPartitionDecommissionResponse defines the response to the request of decommissioning a meta partition.
type MetaPartitionDecommissionResponse struct {
	PartitionID uint64
	VolName     string
	Status      uint8
	Result      string
}

// MetaPartitionLoadRequest defines the request to load meta partition.
type MetaPartitionLoadRequest struct {
	PartitionID uint64
}

// MetaPartitionLoadResponse defines the response to the request of loading meta partition.
type MetaPartitionLoadResponse struct {
	PartitionID uint64
	DoCompare   bool
	ApplyID     uint64
	InodeSign   uint32
	DentrySign  uint32
	Addr        string
}

// VolStatInfo defines the statistics related to a volume
type VolStatInfo struct {
	Name      string
	TotalSize uint64
	UsedSize  uint64
}

// DataPartitionResponse defines the response from a data node to the master that is related to a data partition.
type DataPartitionResponse struct {
	PartitionID uint64
	Status      int8
	ReplicaNum  uint8
	Hosts       []string
	LeaderAddr  string
}

// DataPartitionsView defines the view of a data partition
type DataPartitionsView struct {
	DataPartitions []*DataPartitionResponse
}

func NewDataPartitionsView() (dataPartitionsView *DataPartitionsView) {
	dataPartitionsView = new(DataPartitionsView)
	dataPartitionsView.DataPartitions = make([]*DataPartitionResponse, 0)
	return
}

// MetaPartitionView defines the view of a meta partition
type MetaPartitionView struct {
	PartitionID uint64
	Start       uint64
	End         uint64
	Members     []string
	LeaderAddr  string
	Status      int8
}

// VolView defines the view of a volume
type VolView struct {
	Name           string
	Status         uint8
	MetaPartitions []*MetaPartitionView
	DataPartitions []*DataPartitionResponse
}

func NewVolView(name string, status uint8) (view *VolView) {
	view = new(VolView)
	view.Name = name
	view.Status = status
	view.MetaPartitions = make([]*MetaPartitionView, 0)
	view.DataPartitions = make([]*DataPartitionResponse, 0)
	return
}

func NewMetaPartitionView(partitionID, start, end uint64, status int8) (mpView *MetaPartitionView) {
	mpView = new(MetaPartitionView)
	mpView.PartitionID = partitionID
	mpView.Start = start
	mpView.End = end
	mpView.Status = status
	mpView.Members = make([]string, 0)
	return
}

// SimpleVolView defines the simple view of a volume
type SimpleVolView struct {
	ID           uint64
	Name         string
	Owner        string
	DpReplicaNum uint8
	MpReplicaNum uint8
	Status       uint8
	Capacity     uint64 // GB
	RwDpCnt      int
	MpCnt        int
	DpCnt        int
}
*/
