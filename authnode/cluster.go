package authnode

import (
	"fmt"
	"sync"
	"time"

	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/raftstore"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/errors"
	"github.com/chubaofs/chubaofs/util/keystore"
	"github.com/chubaofs/chubaofs/util/log"
)

// Cluster stores all the cluster-level information.
type Cluster struct {
	Name string
	/*vols                map[string]*Vol
	dataNodes           sync.Map
	metaNodes           sync.Map
	dpMutex             sync.Mutex   // data partition mutex
	volMutex            sync.RWMutex // volume mutex
	createVolMutex      sync.RWMutex // create volume mutex
	mnMutex             sync.RWMutex // meta node mutex
	dnMutex             sync.RWMutex // data node mutex*/
	leaderInfo *LeaderInfo
	cfg        *clusterConfig
	retainLogs uint64
	//idAlloc    *IDAllocator
	/*t                   *topology
	dataNodeStatInfo    *nodeStatInfo
	metaNodeStatInfo    *nodeStatInfo
	volStatInfo         sync.Map
	BadDataPartitionIds *sync.Map*/
	DisableAutoAllocate bool
	fsm                 *KeystoreFsm
	partition           raftstore.Partition

	keystore       map[string]*keystore.KeyInfo
	ksMutex        sync.RWMutex // keystore mutex
	createKeyMutex sync.RWMutex // create key mutex
}

func newCluster(name string, leaderInfo *LeaderInfo, fsm *KeystoreFsm, partition raftstore.Partition, cfg *clusterConfig) (c *Cluster) {
	c = new(Cluster)
	c.Name = name
	c.leaderInfo = leaderInfo
	//c.vols = make(map[string]*Vol, 0)
	c.cfg = cfg
	/*c.t = newTopology()
	c.BadDataPartitionIds = new(sync.Map)
	c.dataNodeStatInfo = new(nodeStatInfo)
	c.metaNodeStatInfo = new(nodeStatInfo)*/
	c.fsm = fsm
	c.partition = partition
	c.keystore = make(map[string]*keystore.KeyInfo, 0)
	//c.idAlloc = newIDAllocator(c.fsm.store, c.partition)
	return
}

func (c *Cluster) scheduleTask() {
	//c.scheduleToCheckDataPartitions()
	//c.scheduleToLoadDataPartitions()
	//c.scheduleToCheckReleaseDataPartitions()
	c.scheduleToCheckHeartbeat()
	//c.scheduleToCheckMetaPartitions()
	//c.scheduleToUpdateStatInfo()
	//c.scheduleToCheckAutoDataPartitionCreation()
	//c.scheduleToCheckVolStatus()
	//c.scheduleToCheckDiskRecoveryProgress()
	//c.scheduleToLoadMetaPartitions()
	//c.scheduleToReduceReplicaNum()
}

func (c *Cluster) masterAddr() (addr string) {
	return c.leaderInfo.addr
}

func (c *Cluster) scheduleToCheckHeartbeat() {
	go func() {
		for {
			if c.partition != nil && c.partition.IsRaftLeader() {
				c.checkLeaderAddr()
				//c.checkDataNodeHeartbeat()
			}
			time.Sleep(time.Second * defaultIntervalToCheckHeartbeat)
		}
	}()
	/*
		go func() {
			for {
				if c.partition != nil && c.partition.IsRaftLeader() {
					c.checkMetaNodeHeartbeat()
				}
				time.Sleep(time.Second * defaultIntervalToCheckHeartbeat)
			}
		}()*/
}

func (c *Cluster) checkLeaderAddr() {
	leaderID, _ := c.partition.LeaderTerm()
	c.leaderInfo.addr = AddrDatabase[leaderID]
}

func (c *Cluster) putKey(k *keystore.KeyInfo) {
	c.ksMutex.Lock()
	defer c.ksMutex.Unlock()
	if _, ok := c.keystore[k.ID]; !ok {
		c.keystore[k.ID] = k
	}
}

func (c *Cluster) getKey(id string) (u *keystore.KeyInfo, err error) {
	c.ksMutex.RLock()
	defer c.ksMutex.RUnlock()
	u, ok := c.keystore[id]
	if !ok {
		err = proto.ErrKeyNotExists
	}
	return
}

// CreateNewKey create a new client to the keystore
func (c *Cluster) CreateNewKey(id string, keyInfo *keystore.KeyInfo) (res *keystore.KeyInfo, err error) {
	c.createKeyMutex.Lock()
	defer c.createKeyMutex.Unlock()
	if _, err = c.getKey(id); err == nil {
		err = proto.ErrDuplicateKey
		goto errHandler
	}
	keyInfo.Ts = time.Now().Unix()
	keyInfo.Key = cryptoutil.GenMasterKey([]byte(keystore.AuthMasterKey), keyInfo.Ts, id)
	if err = c.syncAddKey(keyInfo); err != nil {
		goto errHandler
	}
	res = keyInfo
	c.putKey(keyInfo)
	return
errHandler:
	err = fmt.Errorf("action[CreateNewKey], clusterID[%v] ID:%v, err:%v ", c.Name, keyInfo.Key, err.Error())
	log.LogError(errors.Stack(err))
	//Warn(c.Name, err.Error())
	return
}
