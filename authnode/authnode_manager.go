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

package authnode

import (
	"fmt"
	"strings"

	"github.com/chubaofs/chubaofs/util/log"
	"github.com/tiglabs/raft/proto"
)

// LeaderInfo represents the leader's information
type LeaderInfo struct {
	addr string //host:port
}

func (m *Server) handleLeaderChange(leader uint64) {
	if leader == 0 {
		log.LogWarnf("action[handleLeaderChange] but no leader")
		return
	}
	oldLeaderAddr := m.leaderInfo.addr
	m.leaderInfo.addr = AddrDatabase[leader]
	log.LogWarnf("action[handleLeaderChange] change leader to [%v] ", m.leaderInfo.addr)
	m.reverseProxy = m.newReverseProxy() // TODO why no lock?

	if m.id == leader {
		//Warn(m.clusterName, fmt.Sprintf("clusterID[%v] leader is changed to %v",
		//	m.clusterName, m.leaderInfo.addr))
		if oldLeaderAddr != m.leaderInfo.addr {
			if err := m.cluster.loadKeystore(); err != nil {
				panic(err)
			}
			m.metaReady = true
		}
	}
}

func (m *Server) handlePeerChange(confChange *proto.ConfChange) (err error) {
	var msg string
	addr := string(confChange.Context)
	switch confChange.Type {
	case proto.ConfAddNode:
		var arr []string
		if arr = strings.Split(addr, colonSplit); len(arr) < 2 {
			msg = fmt.Sprintf("action[handlePeerChange] clusterID[%v] nodeAddr[%v] is invalid", m.clusterName, addr)
			break
		}
		m.raftStore.AddNode(confChange.Peer.ID, arr[0])
		AddrDatabase[confChange.Peer.ID] = string(confChange.Context)
		msg = fmt.Sprintf("clusterID[%v] peerID:%v,nodeAddr[%v] has been add", m.clusterName, confChange.Peer.ID, addr)
	case proto.ConfRemoveNode:
		m.raftStore.DeleteNode(confChange.Peer.ID)
		msg = fmt.Sprintf("clusterID[%v] peerID:%v,nodeAddr[%v] has been removed", m.clusterName, confChange.Peer.ID, addr)
	}
	//Warn(m.clusterName, msg)
	log.LogWarnf(msg)
	return
}

func (m *Server) handleApplySnapshot() {
	log.LogInfo("clusterID[%v] peerID:%v action[handleApplySnapshot]", m.clusterName, m.id)
	m.fsm.restore()
	//m.restoreIDAlloc()
	return
}

func (m *Server) restoreIDAlloc() {
	//m.cluster.idAlloc.restore()
}