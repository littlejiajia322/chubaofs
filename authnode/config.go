package authnode

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/chubaofs/chubaofs/raftstore"
	"github.com/tiglabs/raft/proto"
)

//config key
const (
	colonSplit = ":"
	commaSplit = ","
	cfgPeers   = "peers"
	// if the data partition has not been reported within this interval  (in terms of seconds), it will be considered as missing.
	missingDataPartitionInterval        = "missingDataPartitionInterval"
	dataPartitionTimeOutSec             = "dataPartitionTimeOutSec"
	NumberOfDataPartitionsToLoad        = "NumberOfDataPartitionsToLoad"
	secondsToFreeDataPartitionAfterLoad = "secondsToFreeDataPartitionAfterLoad"
	nodeSetCapacity                     = "nodeSetCap"
	heartbeatPortKey                    = "heartbeatPort"
	replicaPortKey                      = "replicaPort"
)

//default value
const (
	defaultTobeFreedDataPartitionCount         = 1000
	defaultSecondsToFreeDataPartitionAfterLoad = 5 * 60 // a data partition can only be freed after loading 5 mins
	defaultIntervalToFreeDataPartition         = 10     // in terms of seconds
	defaultIntervalToCheckHeartbeat            = 60
	defaultIntervalToLoadKeystore              = 5 * 60
	defaultIntervalToCheckDataPartition        = 60
	defaultIntervalToCheckCrc                  = 20 * defaultIntervalToCheckHeartbeat // in terms of seconds
	noHeartBeatTimes                           = 3                                    // number of times that no heartbeat reported
	defaultNodeTimeOutSec                      = noHeartBeatTimes * defaultIntervalToCheckHeartbeat
	defaultDataPartitionTimeOutSec             = 10 * defaultIntervalToCheckHeartbeat
	defaultMissingDataPartitionInterval        = 24 * 3600

	defaultIntervalToAlarmMissingDataPartition = 60 * 60
	timeToWaitForResponse                      = 120         // time to wait for response by the master during loading partition
	defaultPeriodToLoadAllDataPartitions       = 60 * 60 * 4 // how long we need to load all the data partitions on the master every time
	defaultNumberOfDataPartitionsToLoad        = 50          // how many data partitions to load every time
	defaultMetaPartitionTimeOutSec             = 10 * defaultIntervalToCheckHeartbeat
	//DefaultMetaPartitionMissSec                         = 3600

	defaultIntervalToAlarmMissingMetaPartition         = 10 * 60 // interval of checking if a replica is missing
	defaultMetaPartitionMemUsageThreshold      float32 = 0.75    // memory usage threshold on a meta partition
	defaultMaxMetaPartitionCountOnEachNode             = 10000
	defaultReplicaNum                                  = 3
)

type clusterConfig struct {
	peers         []raftstore.PeerAddress
	peerAddrs     []string
	heartbeatPort int64
	replicaPort   int64
}

// AddrDatabase is a map that stores the address of a given host (e.g., the leader)
var AddrDatabase = make(map[uint64]string)

func newClusterConfig() (cfg *clusterConfig) {
	cfg = new(clusterConfig)
	return
}

func parsePeerAddr(peerAddr string) (id uint64, ip string, port uint64, err error) {
	peerStr := strings.Split(peerAddr, colonSplit)
	id, err = strconv.ParseUint(peerStr[0], 10, 64)
	if err != nil {
		return
	}
	port, err = strconv.ParseUint(peerStr[2], 10, 64)
	if err != nil {
		return
	}
	ip = peerStr[1]
	return
}

func (cfg *clusterConfig) parsePeers(peerStr string) error {
	peerArr := strings.Split(peerStr, commaSplit)
	cfg.peerAddrs = peerArr
	for _, peerAddr := range peerArr {
		id, ip, port, err := parsePeerAddr(peerAddr)
		if err != nil {
			return err
		}
		cfg.peers = append(cfg.peers, raftstore.PeerAddress{Peer: proto.Peer{ID: id}, Address: ip})
		address := fmt.Sprintf("%v:%v", ip, port)
		fmt.Println(address)
		AddrDatabase[id] = address
	}
	return nil
}
