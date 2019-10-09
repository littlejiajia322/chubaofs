package authnode

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/log"
)

func (m *Server) startHTTPService() {
	fmt.Printf("start http + %s\n", colonSplit+m.port)
	go func() {
		m.handleFunctions()
		if err := http.ListenAndServe(colonSplit+m.port, nil); err != nil {
			log.LogErrorf("action[startHTTPService] failed,err[%v]", err)
			panic(err)
		}
	}()
	return
}

func (m *Server) newReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{Director: func(request *http.Request) {
		request.URL.Scheme = "http"
		request.URL.Host = m.leaderInfo.addr
	}}
}

func (m *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.LogInfof("URL[%v],remoteAddr[%v]", r.URL, r.RemoteAddr)
	switch r.URL.Path {
	case proto.ClientGetTicket:
		m.getTicket(w, r)
	case proto.AdminCreateKey:
		fallthrough
	case proto.AdminGetKey:
		fallthrough
	case proto.AdminDeleteKey:
		fallthrough
	case proto.AdminAddCaps:
		fallthrough
	case proto.AdminDeleteCaps:
		fallthrough
	case proto.AdminGetCaps:
		m.apiAccessEntry(w, r)
	case proto.AdminAddRaftNode:
		fallthrough
	case proto.AdminRemoveRaftNode:
		m.raftNodeOp(w, r)
	default:
		//TODO
	}
}

func (m *Server) handleFunctions() {
	http.HandleFunc(proto.ClientGetTicket, m.getTicket)
	http.Handle(proto.AdminCreateKey, m.handlerWithInterceptor())
	http.Handle(proto.AdminGetKey, m.handlerWithInterceptor())
	http.Handle(proto.AdminDeleteKey, m.handlerWithInterceptor())
	http.Handle(proto.AdminAddCaps, m.handlerWithInterceptor())
	http.Handle(proto.AdminDeleteCaps, m.handlerWithInterceptor())
	http.Handle(proto.AdminGetCaps, m.handlerWithInterceptor())
	http.Handle(proto.AdminAddRaftNode, m.handlerWithInterceptor())
	http.Handle(proto.AdminRemoveRaftNode, m.handlerWithInterceptor())

	return
}

func (m *Server) handlerWithInterceptor() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if m.partition.IsRaftLeader() {
				if m.metaReady {
					m.ServeHTTP(w, r)
					return
				}
				log.LogWarnf("action[handlerWithInterceptor] leader meta has not ready")
				http.Error(w, m.leaderInfo.addr, http.StatusBadRequest)
				return
			}
			if m.leaderInfo.addr == "" {
				log.LogErrorf("action[handlerWithInterceptor] no leader,request[%v]", r.URL)
				http.Error(w, "no leader", http.StatusBadRequest)
				return
			}
			m.proxy(w, r)
		})
}

func (m *Server) proxy(w http.ResponseWriter, r *http.Request) {
	m.reverseProxy.ServeHTTP(w, r)
}
