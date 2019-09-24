package authnode

import (
	"fmt"
	"net/http"

	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/log"
)

func (m *Server) startHTTPService() {
	fmt.Printf("start http\n")
	go func() {
		m.handleFunctions()
		if err := http.ListenAndServe(colonSplit+m.port, nil); err != nil {
			log.LogErrorf("action[startHTTPService] failed,err[%v]", err)
			panic(err)
		}
	}()
	return
}

/*func (m *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.LogInfof("URL[%v],remoteAddr[%v]", r.URL, r.RemoteAddr)
	switch r.URL.Path {
	case proto.ClientGetTicket:
		m.get(w, r)
	default:

	}
}*/

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
	http.HandleFunc(proto.ClientGetTicket, m.getTicket)
	http.HandleFunc(proto.AdminCreateUser, m.createUser)
	http.HandleFunc(proto.AdminAddCaps, m.addCaps)

	return
}
