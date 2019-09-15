package authnode

import (
	"fmt"
	"net/http/httputil"
	"sync"

	"github.com/chubaofs/chubaofs/util/config"
	//"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/errors"
	//"github.com/chubaofs/chubaofs/util/exporter"
	"github.com/chubaofs/chubaofs/util/log"
)

// Server represents the server in a cluster
type Server struct {
	id          uint64
	clusterName string
	ip          string
	port        string
	walDir      string
	storeDir    string
	retainLogs  uint64
	//leaderInfo   *LeaderInfo
	//config       *clusterConfig
	//cluster      *Cluster
	//rocksDBStore *raftstore.RocksDBStore
	//raftStore    raftstore.RaftStore
	//fsm          *MetadataFsm
	//partition    raftstore.Partition
	wg           sync.WaitGroup
	reverseProxy *httputil.ReverseProxy
	metaReady    bool
}

// configuration keys
const (
	ClusterName       = "clusterName"
	ID                = "id"
	IP                = "ip"
	Port              = "port"
	LogLevel          = "logLevel"
	WalDir            = "walDir"
	StoreDir          = "storeDir"
	GroupID           = 1
	ModuleName        = "master"
	CfgRetainLogs     = "retainLogs"
	DefaultRetainLogs = 20000
	cfgTickInterval   = "tickInterval"
	cfgElectionTick   = "electionTick"
)

// NewServer creates a new server
func NewServer() *Server {
	fmt.Printf("New auth Server\n")
	return &Server{}
}

func (m *Server) checkConfig(cfg *config.Config) (err error) {
	m.clusterName = cfg.GetString(ClusterName)
	m.ip = cfg.GetString(IP)
	m.port = cfg.GetString(Port)
	//m.walDir = cfg.GetString(WalDir)
	//m.storeDir = cfg.GetString(StoreDir)

	return
}

// Start starts a server
func (m *Server) Start(cfg *config.Config) (err error) {
	/*m.config = newClusterConfig()
	m.leaderInfo = &LeaderInfo{}
	m.reverseProxy = m.newReverseProxy()*/
	if err = m.checkConfig(cfg); err != nil {
		log.LogError(errors.Stack(err))
		return
	} /*
		m.rocksDBStore = raftstore.NewRocksDBStore(m.storeDir, LRUCacheSize, WriteBufferSize)
		m.initFsm()
		m.initCluster()
		if err = m.createRaftServer(); err != nil {
			log.LogError(errors.Stack(err))
			return
		}
		m.cluster.partition = m.partition
		m.cluster.idAlloc.partition = m.partition
		m.cluster.scheduleTask()*/
	m.startHTTPService()
	/*exporter.Init(m.clusterName, ModuleName, cfg)
	metricsService := newMonitorMetrics(m.cluster)
	metricsService.start()*/
	m.wg.Add(1)
	return nil
}

// Shutdown closes the server
func (m *Server) Shutdown() {
	m.wg.Done()
}

// Sync waits for the execution termination of the server
func (m *Server) Sync() {
	fmt.Printf("Sync start\n")
	m.wg.Wait()
	fmt.Printf("Sync end\n")
}
