package authnode

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/raftstore"
	"github.com/chubaofs/chubaofs/util/caps"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/util/keystore"
	"github.com/chubaofs/chubaofs/util/log"
)

// Cluster stores all the cluster-level information.
type Cluster struct {
	Name                string
	leaderInfo          *LeaderInfo
	cfg                 *clusterConfig
	retainLogs          uint64
	DisableAutoAllocate bool
	fsm                 *KeystoreFsm
	partition           raftstore.Partition
	keystore            *map[string]*keystore.KeyInfo
	ksMutex             sync.RWMutex // keystore mutex
	opKeyMutex          sync.RWMutex // operations on key mutex
	AuthServiceKey      []byte
}

func newCluster(name string, leaderInfo *LeaderInfo, fsm *KeystoreFsm, partition raftstore.Partition, cfg *clusterConfig) (c *Cluster) {
	c = new(Cluster)
	c.Name = name
	c.leaderInfo = leaderInfo
	c.cfg = cfg
	c.fsm = fsm
	c.partition = partition
	c.keystore = new(map[string]*keystore.KeyInfo)
	//c.idAlloc = newIDAllocator(c.fsm.store, c.partition)
	return
}

func (c *Cluster) scheduleTask() {
	c.scheduleToCheckHeartbeat()
	c.scheduleToLoadKeystore()
}

func (c *Cluster) masterAddr() (addr string) {
	return c.leaderInfo.addr
}

func (c *Cluster) scheduleToCheckHeartbeat() {
	go func() {
		for {
			if c.partition != nil && c.partition.IsRaftLeader() {
				c.checkLeaderAddr()
			}
			time.Sleep(time.Second * defaultIntervalToCheckHeartbeat)
		}
	}()
}

// TODO: add lock, implemented as raftcmd
func (c *Cluster) scheduleToLoadKeystore() {
	go func() {
		for {
			time.Sleep(time.Second * defaultIntervalToLoadKeystore)
			if c.partition != nil && !c.partition.IsRaftLeader() {
				c.clearKeystore()
				c.loadKeystore()
			}
			//time.Sleep(time.Second * defaultIntervalToLoadKeystore)
		}
	}()
}

func (c *Cluster) checkLeaderAddr() {
	leaderID, _ := c.partition.LeaderTerm()
	c.leaderInfo.addr = AddrDatabase[leaderID]
}

func (c *Cluster) putKey(k *keystore.KeyInfo) {
	c.ksMutex.Lock()
	defer c.ksMutex.Unlock()
	if _, ok := (*c.keystore)[k.ID]; !ok {
		(*c.keystore)[k.ID] = k
	}
}

func (c *Cluster) getKey(id string) (u *keystore.KeyInfo, err error) {
	c.ksMutex.RLock()
	defer c.ksMutex.RUnlock()
	u, ok := (*c.keystore)[id]
	if !ok {
		err = proto.ErrKeyNotExists
	}
	return
}

func (c *Cluster) deleteKey(id string) {
	c.ksMutex.Lock()
	defer c.ksMutex.Unlock()
	delete((*c.keystore), id)
	return
}

// CreateNewKey create a new key to the keystore
func (c *Cluster) CreateNewKey(id string, keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	c.opKeyMutex.Lock()
	defer c.opKeyMutex.Unlock()
	if _, err = c.getKey(id); err == nil {
		err = proto.ErrDuplicateKey
		goto errHandler
	}
	keyInfo.Ts = time.Now().Unix()
	keyInfo.Key = cryptoutil.GenMasterKey([]byte(c.AuthServiceKey), keyInfo.Ts, id)
	if err = c.syncAddKey(keyInfo); err != nil {
		goto errHandler
	}
	res = keyInfo
	c.putKey(keyInfo)
	return
errHandler:
	err = fmt.Errorf("action[CreateNewKey], clusterID[%v] ID:%v, err:%v ", c.Name, keyInfo, err.Error())
	log.LogError(errors.Stack(err))
	//Warn(c.Name, err.Error())
	return
}

// DeleteKey delete a key from the keystore
func (c *Cluster) DeleteKey(id string) (res *keystore.KeyInfo, err error) {
	c.opKeyMutex.Lock()
	defer c.opKeyMutex.Unlock()
	if res, err = c.getKey(id); err != nil {
		err = proto.ErrKeyNotExists
		goto errHandler
	}
	if err = c.syncDeleteKey(res); err != nil {
		goto errHandler
	}
	c.deleteKey(id)
	return
errHandler:
	err = fmt.Errorf("action[DeleteKey], clusterID[%v] ID:%v, err:%v ", c.Name, id, err.Error())
	log.LogError(errors.Stack(err))
	//Warn(c.Name, err.Error())
	return
}

// GetKey get a key from the keystore
func (c *Cluster) GetKey(id string) (res *keystore.KeyInfo, err error) {
	if res, err = c.getKey(id); err != nil {
		err = proto.ErrKeyNotExists
		goto errHandler
	}
	return
errHandler:
	err = fmt.Errorf("action[GetKey], clusterID[%v] ID:%v, err:%v ", c.Name, id, err.Error())
	log.LogError(errors.Stack(err))
	//Warn(c.Name, err.Error())
	return
}

// AddCaps add caps to the key
func (c *Cluster) AddCaps(id string, keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	var (
		addCaps *caps.Caps
		curCaps *caps.Caps
		newCaps []byte
	)
	c.opKeyMutex.Lock()
	defer c.opKeyMutex.Unlock()
	if res, err = c.getKey(id); err != nil {
		err = proto.ErrKeyNotExists
		goto errHandler
	}

	addCaps = &caps.Caps{}
	if err = addCaps.Init(keyInfo.Caps); err != nil {
		goto errHandler
	}
	curCaps = &caps.Caps{}
	if err = curCaps.Init(res.Caps); err != nil {
		goto errHandler
	}
	curCaps.Union(addCaps)
	if newCaps, err = json.Marshal(curCaps); err != nil {
		goto errHandler
	}
	res.Caps = newCaps
	if err = c.syncAddCaps(res); err != nil {
		goto errHandler
	}
	c.putKey(res)
	return
errHandler:
	err = fmt.Errorf("action[AddCaps], clusterID[%v] ID:%v, err:%v ", c.Name, keyInfo, err.Error())
	log.LogError(errors.Stack(err))
	//Warn(c.Name, err.Error())
	return
}

// DeleteCaps delete caps from the key
func (c *Cluster) DeleteCaps(id string, keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	var (
		delCaps *caps.Caps
		curCaps *caps.Caps
		newCaps []byte
	)
	c.opKeyMutex.Lock()
	defer c.opKeyMutex.Unlock()
	if res, err = c.getKey(id); err != nil {
		err = proto.ErrKeyNotExists
		goto errHandler
	}

	delCaps = &caps.Caps{}
	if err = delCaps.Init(keyInfo.Caps); err != nil {
		return
	}
	curCaps = &caps.Caps{}
	if err = curCaps.Init(res.Caps); err != nil {
		return
	}

	curCaps.Delete(delCaps)

	if newCaps, err = json.Marshal(curCaps); err != nil {
		goto errHandler
	}
	res.Caps = newCaps
	if err = c.syncDeleteCaps(res); err != nil {
		goto errHandler
	}
	c.putKey(res)
	return
errHandler:
	err = fmt.Errorf("action[DeleteCaps], clusterID[%v] ID:%v, err:%v ", c.Name, keyInfo, err.Error())
	log.LogError(errors.Stack(err))
	//Warn(c.Name, err.Error())
	return
}