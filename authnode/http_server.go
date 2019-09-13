package authnode

import "net/http"

func (m *Server) startHTTPService() {
	go func() {
		m.handleFunctions()
		if err := http.ListenAndServe(colonSplit+m.port, nil); err != nil {
			log.LogErrorf("action[startHTTPService] failed,err[%v]", err)
			panic(err)
		}
	}()
	return
}
