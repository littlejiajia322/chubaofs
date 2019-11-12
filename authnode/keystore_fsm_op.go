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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/chubaofs/chubaofs/util/keystore"
	"github.com/chubaofs/chubaofs/util/log"
	"github.com/tiglabs/raft/proto"
)

// RaftCmd defines the Raft commands.
type RaftCmd struct {
	Op uint32 `json:"op"`
	K  string `json:"k"`
	V  []byte `json:"v"`
}

// Marshal converts the RaftCmd to a byte array.
func (m *RaftCmd) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal converts the byte array to a RaftCmd.
func (m *RaftCmd) Unmarshal(data []byte) (err error) {
	return json.Unmarshal(data, m)
}

func (m *RaftCmd) setOpType() {
	keyArr := strings.Split(m.K, keySeparator)
	if len(keyArr) < 2 {
		log.LogWarnf("action[setOpType] invalid length[%v]", keyArr)
		return
	}
	switch keyArr[1] {
	case keyAcronym:
		m.Op = opSyncAddKey
	default:
		log.LogWarnf("action[setOpType] unknown opCode[%v]", keyArr[1])
	}
}

// KeyInfoValue define the values for a key
type KeyInfoValue struct {
	ID   string `json:"id"`
	Key  []byte `json:"key"`
	Ts   int64  `json:"create_ts"`
	Role string `json:"role"`
	Caps []byte `json:"caps"`
}

func newKeyInfoValue(keyInfo *keystore.KeyInfo) (vv *KeyInfoValue) {
	vv = &KeyInfoValue{
		ID:   keyInfo.ID,
		Key:  keyInfo.Key,
		Ts:   keyInfo.Ts,
		Role: keyInfo.Role,
		Caps: keyInfo.Caps,
	}
	return
}

func (c *Cluster) submit(metadata *RaftCmd) (err error) {
	cmd, err := metadata.Marshal()
	if err != nil {
		return errors.New(err.Error())
	}
	if _, err = c.partition.Submit(cmd); err != nil {
		msg := fmt.Sprintf("action[keystore_submit] err:%v", err.Error())
		return errors.New(msg)
	}
	return
}

func (c *Cluster) syncAddKey(keyInfo *keystore.KeyInfo) (err error) {
	return c.syncPutKeyInfo(opSyncAddKey, keyInfo)
}

func (c *Cluster) syncAddCaps(keyInfo *keystore.KeyInfo) (err error) {
	return c.syncPutKeyInfo(opSyncAddCaps, keyInfo)
}

func (c *Cluster) syncDeleteKey(keyInfo *keystore.KeyInfo) (err error) {
	return c.syncPutKeyInfo(opSyncDeleteKey, keyInfo)
}

func (c *Cluster) syncDeleteCaps(keyInfo *keystore.KeyInfo) (err error) {
	return c.syncPutKeyInfo(opSyncDeleteCaps, keyInfo)
}

func (c *Cluster) syncPutKeyInfo(opType uint32, keyInfo *keystore.KeyInfo) (err error) {
	keydata := new(RaftCmd)
	keydata.Op = opType
	keydata.K = ksPrefix + keyInfo.ID
	vv := newKeyInfoValue(keyInfo)
	if keydata.V, err = json.Marshal(vv); err != nil {
		return errors.New(err.Error())
	}
	return c.submit(keydata)
}

func (c *Cluster) loadKeystore() (err error) {
	ks := make(map[string]*keystore.KeyInfo, 0)
	log.LogInfof("action[loadKeystore]")
	result, err := c.fsm.store.SeekForPrefix([]byte(ksPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadKeystore],err:%v", err.Error())
		return err
	}
	for _, value := range result {
		k := &keystore.KeyInfo{}
		if err = json.Unmarshal(value, k); err != nil {
			err = fmt.Errorf("action[loadKeystore],value:%v,unmarshal err:%v", string(value), err)
			return err
		}
		if _, ok := ks[k.ID]; !ok {
			ks[k.ID] = k
		}
		log.LogInfof("action[loadKeystore],key[%v]", k)
	}
	c.ksMutex.Lock()
	defer c.ksMutex.Unlock()
	c.keystore = &ks

	return
}

func (c *Cluster) clearKeystore() {
	c.ksMutex.Lock()
	defer c.ksMutex.Unlock()
	c.keystore = nil
}

func (c *Cluster) addRaftNode(nodeID uint64, addr string) (err error) {
	peer := proto.Peer{ID: nodeID}
	_, err = c.partition.ChangeMember(proto.ConfAddNode, peer, []byte(addr))
	if err != nil {
		return errors.New("action[addRaftNode] error: " + err.Error())
	}
	return nil
}

func (c *Cluster) removeRaftNode(nodeID uint64, addr string) (err error) {
	peer := proto.Peer{ID: nodeID}
	_, err = c.partition.ChangeMember(proto.ConfRemoveNode, peer, []byte(addr))
	if err != nil {
		return errors.New("action[removeRaftNode] error: " + err.Error())
	}
	return nil
}
