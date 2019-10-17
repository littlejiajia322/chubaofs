package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"

	"net/http"
	"net/url"
	"os"
	"time"
	"unsafe"

	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/config"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/keystore"
)

// requst path
const (
	CreateKey      = "createkey"
	DeleteKey      = "deletekey"
	GetKey         = "getkey"
	AddCaps        = "addcaps"
	DeleteCaps     = "deletecaps"
	AddRaftNode    = "addraftnode"
	RemoveRaftNode = "removeraftnode"
)

var (
	isTicket bool
	flaginfo flagInfo
)

type ticketFlag struct {
	key    string
	url    string
	output string
}

type apiFlag struct {
	ticket  string
	url     string
	service string
	request string
	data    string
	output  string
}

type flagInfo struct {
	ticket ticketFlag
	api    apiFlag
}

type keyRing struct {
	ID  string `json:"id"`
	Key []byte `json:"key"`
}

type ticketFile struct {
	ID        string `json:"id"`
	Key       string `json:"session_key"`
	ServiceID string `json:"service_id"`
	Ticket    string `json:"ticket"`
}

func (m *ticketFile) dumpJSONFile(filename string) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err)
	}

	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	_, err = io.WriteString(file, string(data))
	if err != nil {
		panic(err)
	}
}

func sendReq(u string, data interface{}) (res []byte) {
	// We can use POST form to get result, too.
	// http://localhost:8081/client/getticket
	messageJSON, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	message := base64.StdEncoding.EncodeToString(messageJSON)

	//resp, err := http.PostForm(u, url.Values{authnode.ClientMessage: {message}})
	resp, err := http.PostForm(u, url.Values{"Token": {message}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	res = body
	return
}

func genVerifier(key []byte) (v string, ts int64, err error) {
	ts = time.Now().Unix()
	tsbuf := make([]byte, unsafe.Sizeof(ts))
	binary.LittleEndian.PutUint64(tsbuf, uint64(ts))
	if v, err = cryptoutil.EncodeMessage(tsbuf, key); err != nil {
		panic(err)
	}
	return
}

func getTicketFromAuth(keyring *keyRing) (ticketfile ticketFile) {

	var (
		err     error
		ts      int64
		msgResp proto.AuthGetTicketResp
	)

	// construct request body
	messageStruct := proto.AuthGetTicketReq{
		Type:      proto.MsgAuthTicketReq,
		ClientID:  keyring.ID,
		ServiceID: proto.AuthServiceID,
	}

	if messageStruct.Verifier, ts, err = genVerifier(keyring.Key); err != nil {
		panic(err)
	}

	body := sendReq(flaginfo.ticket.url, messageStruct)

	fmt.Printf("\n" + string(body) + "\n")

	if msgResp, err = proto.ParseAuthGetTicketResp(body, keyring.Key); err != nil {
		panic(err)
	}

	verifyTicketRespComm(&msgResp, proto.MsgAuthTicketReq, keyring.ID, proto.AuthServiceID, ts)

	ticketfile.Ticket = msgResp.Ticket
	ticketfile.ServiceID = msgResp.ServiceID
	ticketfile.Key = cryptoutil.Base64Encode(msgResp.SessionKey.Key)
	ticketfile.ID = keyring.ID

	return
}

func getTicket() {
	cfg := config.LoadConfigFile(flaginfo.ticket.key)
	key, err := cryptoutil.Base64Decode(cfg.GetString("key"))
	if err != nil {
		panic(err)
	}
	keyring := keyRing{
		ID:  cfg.GetString("id"),
		Key: key,
	}

	ticketfile := getTicketFromAuth(&keyring)
	ticketfile.dumpJSONFile(flaginfo.ticket.output)

	return
}

func accessAuthServer() {
	var (
		msg        proto.MsgType
		sessionKey []byte
		err        error
		message    interface{}
		ts         int64
		res        string
	)

	switch flaginfo.api.request {
	case CreateKey:
		msg = proto.MsgAuthCreateKeyReq
	case DeleteKey:
		msg = proto.MsgAuthDeleteKeyReq
	case GetKey:
		msg = proto.MsgAuthGetKeyReq
	case AddCaps:
		msg = proto.MsgAuthAddCapsReq
	case DeleteCaps:
		msg = proto.MsgAuthDeleteCapsReq
	case AddRaftNode:
		msg = proto.MsgAuthAddRaftNodeReq
	case RemoveRaftNode:
		msg = proto.MsgAuthRemoveRaftNodeReq
	default:
		panic(fmt.Errorf("wrong requst [%s]", flaginfo.api.request))
	}

	ticketCFG := config.LoadConfigFile(flaginfo.api.ticket)

	apiReq := &proto.APIAccessReq{
		Type:      msg,
		ClientID:  ticketCFG.GetString("id"),
		ServiceID: proto.AuthServiceID,
	}

	if sessionKey, err = cryptoutil.Base64Decode(ticketCFG.GetString("session_key")); err != nil {
		panic(err)
	}

	if apiReq.Verifier, ts, err = genVerifier(sessionKey); err != nil {
		panic(err)
	}
	apiReq.Ticket = ticketCFG.GetString("ticket")

	dataCFG := config.LoadConfigFile(flaginfo.api.data)

	switch flaginfo.api.request {
	case CreateKey:
		message = proto.AuthAPIAccessReq{
			APIReq: *apiReq,
			KeyInfo: keystore.KeyInfo{
				ID:   dataCFG.GetString("id"),
				Role: dataCFG.GetString("role"),
				Caps: []byte(dataCFG.GetString("caps")),
			},
		}
	case DeleteKey:
		message = proto.AuthAPIAccessReq{
			APIReq: *apiReq,
			KeyInfo: keystore.KeyInfo{
				ID: dataCFG.GetString("id"),
			},
		}
	case GetKey:
		message = proto.AuthAPIAccessReq{
			APIReq: *apiReq,
			KeyInfo: keystore.KeyInfo{
				ID: dataCFG.GetString("id"),
			},
		}
	case AddCaps:
		message = proto.AuthAPIAccessReq{
			APIReq: *apiReq,
			KeyInfo: keystore.KeyInfo{
				ID:   dataCFG.GetString("id"),
				Caps: []byte(dataCFG.GetString("caps")),
			},
		}
	case DeleteCaps:
		message = proto.AuthAPIAccessReq{
			APIReq: *apiReq,
			KeyInfo: keystore.KeyInfo{
				ID:   dataCFG.GetString("id"),
				Caps: []byte(dataCFG.GetString("caps")),
			},
		}
	case AddRaftNode:
		fallthrough
	case RemoveRaftNode:
		message = proto.AuthRaftNodeReq{
			APIReq: *apiReq,
			RaftNodeInfo: proto.AuthRaftNodeInfo{
				ID:   uint64(dataCFG.GetInt64("id")),
				Addr: dataCFG.GetString("addr"),
			},
		}
	default:
		panic(fmt.Errorf("wrong action [%s]", flaginfo.api.request))
	}

	body := sendReq(flaginfo.api.url, message)
	fmt.Printf("\nbody: " + string(body) + "\n")

	switch flaginfo.api.request {
	case CreateKey:
		fallthrough
	case DeleteKey:
		fallthrough
	case GetKey:
		fallthrough
	case AddCaps:
		fallthrough
	case DeleteCaps:
		var resp proto.AuthAPIAccessResp
		if resp, err = proto.ParseAuthAPIAccessResp(body, sessionKey); err != nil {
			panic(err)
		}

		verifyRespComm(&resp.APIResp, msg, ticketCFG.GetString("id"), proto.AuthServiceID, ts)

		if flaginfo.api.request == CreateKey {
			if err = resp.KeyInfo.DumpJSONFile(flaginfo.api.output); err != nil {
				panic(err)
			}
		} else {
			if res, err = resp.KeyInfo.DumpJSONStr(); err != nil {
				panic(err)
			}
			fmt.Printf(res + "\n")
		}
	case AddRaftNode:
		fallthrough
	case RemoveRaftNode:
		var resp proto.AuthRaftNodeResp
		if resp, err = proto.ParseAuthRaftNodeResp(body, sessionKey); err != nil {
			panic(err)
		}

		verifyRespComm(&resp.APIResp, msg, ticketCFG.GetString("id"), proto.AuthServiceID, ts)

		fmt.Printf(resp.Msg + "\n")
	}

	return

}

func verifyTicketRespComm(ticketResp *proto.AuthGetTicketResp, msg proto.MsgType, clientID string, serviceID string, ts int64) {
	if ts+1 != ticketResp.Verifier {
		panic("verifier verification failed")
	}

	if ticketResp.Type != msg+1 {
		panic("msg verification failed")
	}

	if ticketResp.ClientID != clientID {
		panic("id verification failed")
	}

	if ticketResp.ServiceID != serviceID {
		panic("service id verification failed")
	}
	return
}

func verifyRespComm(apiResp *proto.APIAccessResp, msg proto.MsgType, clientID string, serviceID string, ts int64) {
	if ts+1 != apiResp.Verifier {
		panic("verifier verification failed")
	}

	if apiResp.Type != msg+1 {
		panic("msg verification failed")
	}

	if apiResp.ClientID != clientID {
		panic("id verification failed")
	}

	if apiResp.ServiceID != serviceID {
		panic("service id verification failed")
	}
	return
}

func accessAPI() {
	switch flaginfo.api.service {
	case "auth":
		accessAuthServer()
	default:
		panic(fmt.Errorf("server type error [%s]", flaginfo.api.service))
	}
}

func main() {
	ticketCmd := flag.NewFlagSet("ticket", flag.ExitOnError)
	apiCmd := flag.NewFlagSet("api", flag.ExitOnError)

	switch os.Args[1] {
	case "ticket":
		isTicket = true
	case "api":
		isTicket = false
	default:
		fmt.Println("expected 'ticket' or 'api' subcommands")
		os.Exit(1)
	}

	if isTicket {
		key := ticketCmd.String("keyfile", "", "path to key file")
		url := ticketCmd.String("url", "", "api url")
		file := ticketCmd.String("output", "", "output path to ticket file")
		ticketCmd.Parse(os.Args[2:])
		flaginfo.ticket.key = *key
		flaginfo.ticket.url = *url
		flaginfo.ticket.output = *file
		getTicket()
	} else {
		ticket := apiCmd.String("ticketfile", "", "path to ticket file")
		url := apiCmd.String("url", "", "api url")
		data := apiCmd.String("data", "", "request data file")
		output := apiCmd.String("output", "", "output path to keyring file")
		apiCmd.Parse(os.Args[2:])
		flaginfo.api.ticket = *ticket
		flaginfo.api.url = *url
		flaginfo.api.data = *data
		flaginfo.api.output = *output
		if len(apiCmd.Args()) >= 2 {
			flaginfo.api.service = apiCmd.Args()[0]
			flaginfo.api.request = apiCmd.Args()[1]
		} else {
			panic(fmt.Errorf("requst parameter needed"))
		}
		accessAPI()
	}
}
