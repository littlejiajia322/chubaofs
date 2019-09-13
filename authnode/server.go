package authnode

import (
	"net/http/httputil"
	"sync"

	//"github.com/go-delve/delve/pkg/config"
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
	m.reverseProxy = m.newReverseProxy()
	if err = m.checkConfig(cfg); err != nil {
		log.LogError(errors.Stack(err))
		return
	}
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
	metricsService.start()
	m.wg.Add(1)*/
	return nil
}

func (m *Server) handleFunctions() {
	/*
	http.HandleFunc(proto.AdminGetIP, m.getIPAddr)
	http.Handle(proto.AdminGetCluster, m.handlerWithInterceptor())
	http.Handle(proto.AdminGetDataPartition, m.handlerWithInterceptor())
	http.Handle(proto.AdminCreateDataPartition, m.handlerWithInterceptor())
	http.Handle(proto.AdminLoadDataPartition, m.handlerWithInterceptor())
	http.Handle(proto.AdminDecommissionDataPartition, m.handlerWithInterceptor())
	http.Handle(proto.AdminCreateVol, m.handlerWithInterceptor())
	http.Handle(proto.AdminGetVol, m.handlerWithInterceptor())
	http.Handle(proto.AdminDeleteVol, m.handlerWithInterceptor())
	http.Handle(proto.AdminUpdateVol, m.handlerWithInterceptor())
	http.Handle(proto.AdminClusterFreeze, m.handlerWithInterceptor())
	http.Handle(proto.AddDataNode, m.handlerWithInterceptor())
	http.Handle(proto.AddMetaNode, m.handlerWithInterceptor())
	http.Handle(proto.DecommissionDataNode, m.handlerWithInterceptor())
	http.Handle(proto.DecommissionDisk, m.handlerWithInterceptor())
	http.Handle(proto.DecommissionMetaNode, m.handlerWithInterceptor())
	http.Handle(proto.GetDataNode, m.handlerWithInterceptor())
	http.Handle(proto.GetMetaNode, m.handlerWithInterceptor())
	http.Handle(proto.AdminLoadMetaPartition, m.handlerWithInterceptor())
	http.Handle(proto.AdminDecommissionMetaPartition, m.handlerWithInterceptor())
	http.Handle(proto.ClientDataPartitions, m.handlerWithInterceptor())
	http.Handle(proto.ClientVol, m.handlerWithInterceptor())
	http.Handle(proto.ClientMetaPartitions, m.handlerWithInterceptor())
	http.Handle(proto.ClientMetaPartition, m.handlerWithInterceptor())
	http.Handle(proto.GetDataNodeTaskResponse, m.handlerWithInterceptor())
	http.Handle(proto.GetMetaNodeTaskResponse, m.handlerWithInterceptor())
	http.Handle(proto.AdminCreateMP, m.handlerWithInterceptor())
	http.Handle(proto.ClientVolStat, m.handlerWithInterceptor())
	http.Handle(proto.AddRaftNode, m.handlerWithInterceptor())
	http.Handle(proto.RemoveRaftNode, m.handlerWithInterceptor())
	http.Handle(proto.AdminSetMetaNodeThreshold, m.handlerWithInterceptor())
	http.Handle(proto.GetTopologyView, m.handlerWithInterceptor())
*/
	return
}
