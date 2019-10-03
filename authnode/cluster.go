package authnode

import (
	"time"

	"github.com/chubaofs/chubaofs/raftstore"
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
