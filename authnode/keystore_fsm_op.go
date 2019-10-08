package authnode

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/chubaofs/chubaofs/util/keystore"
	"github.com/chubaofs/chubaofs/util/log"
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

func (m *RaftCmd) setOpType() { /*
		keyArr := strings.Split(m.K, keySeparator)
		if len(keyArr) < 2 {
			log.LogWarnf("action[setOpType] invalid length[%v]", keyArr)
			return
		}
		switch keyArr[1] {
		case metaNodeAcronym:
			m.Op = opSyncAddMetaNode
		case dataNodeAcronym:
			m.Op = opSyncAddDataNode
		case dataPartitionAcronym:
			m.Op = opSyncAddDataPartition
		case metaPartitionAcronym:
			m.Op = opSyncAddMetaPartition
		case volAcronym:
			m.Op = opSyncAddVol
		case clusterAcronym:
			m.Op = opSyncPutCluster
		case nodeSetAcronym:
			m.Op = opSyncAddNodeSet
		case maxDataPartitionIDKey:
			m.Op = opSyncAllocDataPartitionID
		case maxMetaPartitionIDKey:
			m.Op = opSyncAllocMetaPartitionID
		case maxCommonIDKey:
			m.Op = opSyncAllocCommonID
		default:
			log.LogWarnf("action[setOpType] unknown opCode[%v]", keyArr[1])
	*/
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
		msg := fmt.Sprintf("action[metadata_submit] err:%v", err.Error())
		return errors.New(msg)
	}
	return
}

//key=#vol#volID,value=json.Marshal(vv)
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
		//c.putKey(u)
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
