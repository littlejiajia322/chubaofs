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

package errors

//err
var (
	ErrSuc                    = New("success")
	ErrInternalError          = New("internal error")
	ErrParamError             = New("parameter error")
	ErrInvalidCfg             = New("bad configuration file")
	ErrPersistenceByRaft      = New("persistence by raft occurred error")
	ErrMarshalData            = New("marshal data error")
	ErrUnmarshalData          = New("unmarshal data error")
	ErrVolNotExists           = New("vol not exists")
	ErrMetaPartitionNotExists = New("meta partition not exists")
	ErrDataPartitionNotExists = New("data partition not exists")
	ErrDataNodeNotExists      = New("data node not exists")
	ErrMetaNodeNotExists      = New("meta node not exists")
	ErrDuplicateVol           = New("duplicate vol")
	ErrActiveDataNodesTooLess = New("no enough active data node")
	ErrActiveMetaNodesTooLess = New("no enough active meta node")
	ErrInvalidMpStart         = New("invalid meta partition start value")
	ErrNoAvailDataPartition   = New("no available data partition")
	ErrReshuffleArray         = New("the array to be reshuffled is nil")

	ErrIllegalDataReplica = New("data replica is illegal")

	ErrMissingReplica       = New("a missing data replica is found")
	ErrHasOneMissingReplica = New("there is a missing data replica")

	ErrNoDataNodeToWrite = New("No data node available for creating a data partition")
	ErrNoMetaNodeToWrite = New("No meta node available for creating a meta partition")

	ErrCannotBeOffLine                 = New("cannot take the data replica offline")
	ErrNoDataNodeToCreateDataPartition = New("no enough data nodes for creating a data partition")
	ErrNoRackToCreateDataPartition     = New("no rack available for creating a data partition")
	ErrNoNodeSetToCreateDataPartition  = New("no node set available for creating a data partition")
	ErrNoNodeSetToCreateMetaPartition  = New("no node set available for creating a meta partition")
	ErrNoMetaNodeToCreateMetaPartition = New("no enough meta nodes for creating a meta partition")
	ErrIllegalMetaReplica              = New("illegal meta replica")
	ErrNoEnoughReplica                 = New("no enough replicas")
	ErrNoLeader                        = New("no leader")
	ErrVolAuthKeyNotMatch              = New("client and server auth key do not match")
	ErrAuthKeyStoreError               = New("auth keystore error")
	ErrAuthAPIAccessGenRespError       = New("auth API access response error")
	ErrKeyNotExists                    = New("key not exists")
	ErrDuplicateKey                    = New("duplicate key")
	ErrInvalidTicket                   = New("invalid ticket")
	ErrExpiredTicket                   = New("expired ticket")
	ErrMasterAPIGenRespError           = New("master API generate response error")
)

// http response error code and error message definitions
const (
	ErrCodeSuccess = iota
	ErrCodeInternalError
	ErrCodeParamError
	ErrCodeInvalidCfg
	ErrCodePersistenceByRaft
	ErrCodeMarshalData
	ErrCodeUnmarshalData
	ErrCodeVolNotExists
	ErrCodeMetaPartitionNotExists
	ErrCodeDataPartitionNotExists
	ErrCodeDataNodeNotExists
	ErrCodeMetaNodeNotExists
	ErrCodeDuplicateVol
	ErrCodeActiveDataNodesTooLess
	ErrCodeActiveMetaNodesTooLess
	ErrCodeInvalidMpStart
	ErrCodeNoAvailDataPartition
	ErrCodeReshuffleArray
	ErrCodeIllegalDataReplica
	ErrCodeMissingReplica
	ErrCodeHasOneMissingReplica
	ErrCodeNoDataNodeToWrite
	ErrCodeNoMetaNodeToWrite
	ErrCodeCannotBeOffLine
	ErrCodeNoDataNodeToCreateDataPartition
	ErrCodeNoRackToCreateDataPartition
	ErrCodeNoNodeSetToCreateDataPartition
	ErrCodeNoNodeSetToCreateMetaPartition
	ErrCodeNoMetaNodeToCreateMetaPartition
	ErrCodeIllegalMetaReplica
	ErrCodeNoEnoughReplica
	ErrCodeNoLeader
	ErrCodeVolAuthKeyNotMatch
	ErrCodeAuthKeyStoreError
	ErrCodeAuthAPIAccessGenRespError
	ErrCodeAuthRaftNodeGenRespError
	ErrCodeAuthReqRedirectError
	ErrCodeInvalidTicket
	ErrCodeExpiredTicket
	ErrCodeMasterAPIGenRespError
)

// Err2CodeMap error map to code
var Err2CodeMap = map[error]int32{
	ErrSuc:                             ErrCodeSuccess,
	ErrInternalError:                   ErrCodeInternalError,
	ErrParamError:                      ErrCodeParamError,
	ErrInvalidCfg:                      ErrCodeInvalidCfg,
	ErrPersistenceByRaft:               ErrCodePersistenceByRaft,
	ErrMarshalData:                     ErrCodeMarshalData,
	ErrUnmarshalData:                   ErrCodeUnmarshalData,
	ErrVolNotExists:                    ErrCodeVolNotExists,
	ErrMetaPartitionNotExists:          ErrCodeMetaPartitionNotExists,
	ErrDataPartitionNotExists:          ErrCodeDataPartitionNotExists,
	ErrDataNodeNotExists:               ErrCodeDataNodeNotExists,
	ErrMetaNodeNotExists:               ErrCodeMetaNodeNotExists,
	ErrDuplicateVol:                    ErrCodeDuplicateVol,
	ErrActiveDataNodesTooLess:          ErrCodeActiveDataNodesTooLess,
	ErrActiveMetaNodesTooLess:          ErrCodeActiveMetaNodesTooLess,
	ErrInvalidMpStart:                  ErrCodeInvalidMpStart,
	ErrNoAvailDataPartition:            ErrCodeNoAvailDataPartition,
	ErrReshuffleArray:                  ErrCodeReshuffleArray,
	ErrIllegalDataReplica:              ErrCodeIllegalDataReplica,
	ErrMissingReplica:                  ErrCodeMissingReplica,
	ErrHasOneMissingReplica:            ErrCodeHasOneMissingReplica,
	ErrNoDataNodeToWrite:               ErrCodeNoDataNodeToWrite,
	ErrNoMetaNodeToWrite:               ErrCodeNoMetaNodeToWrite,
	ErrCannotBeOffLine:                 ErrCodeCannotBeOffLine,
	ErrNoDataNodeToCreateDataPartition: ErrCodeNoDataNodeToCreateDataPartition,
	ErrNoRackToCreateDataPartition:     ErrCodeNoRackToCreateDataPartition,
	ErrNoNodeSetToCreateDataPartition:  ErrCodeNoNodeSetToCreateDataPartition,
	ErrNoNodeSetToCreateMetaPartition:  ErrCodeNoNodeSetToCreateMetaPartition,
	ErrNoMetaNodeToCreateMetaPartition: ErrCodeNoMetaNodeToCreateMetaPartition,
	ErrIllegalMetaReplica:              ErrCodeIllegalMetaReplica,
	ErrNoEnoughReplica:                 ErrCodeNoEnoughReplica,
	ErrNoLeader:                        ErrCodeNoLeader,
	ErrVolAuthKeyNotMatch:              ErrCodeVolAuthKeyNotMatch,
	ErrAuthKeyStoreError:               ErrCodeAuthKeyStoreError,
	ErrAuthAPIAccessGenRespError:       ErrCodeAuthAPIAccessGenRespError,
	ErrInvalidTicket:                   ErrCodeInvalidTicket,
	ErrExpiredTicket:                   ErrCodeExpiredTicket,
	ErrMasterAPIGenRespError:           ErrCodeMasterAPIGenRespError,
}
