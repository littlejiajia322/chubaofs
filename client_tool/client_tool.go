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

	"github.com/chubaofs/chubaofs/authnode"
	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/config"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/keystore"
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
}

type flagInfo struct {
	ticket ticketFlag
	api    apiFlag
}

type keyRing struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type ticketFile struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Ticket string `json:"ticket"`
}

func (m *ticketFile) dump(filename string) {
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

	resp, err := http.PostForm(u, url.Values{authnode.ClientMessage: {message}})
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
	if v, err = cryptoutil.EncodeMessage(tsbuf, []byte(key)); err != nil {
		panic(err)
	}
	return
}

func getTicketFromAuth(keyring *keyRing) (ticketfile ticketFile) {
	var (
		err error
		ts  int64
		//msgResp proto.AuthGetTicketResp
	)

	// construct request body
	messageStruct := proto.AuthGetTicketReq{
		Type:      proto.MsgAuthTicketReq,
		ClientID:  keyring.ID,
		ServiceID: proto.AuthServiceID,
	}

	if messageStruct.Verifier, ts, err = genVerifier([]byte(keyring.Key)); err != nil {
		panic(err)
	}

	body := sendReq(flaginfo.ticket.url, messageStruct)

	var parser *proto.SecRespParser
	parser, err = proto.CreateSecRespParser(body, []byte(keyring.Key))
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d %s %s %d\n", parser.Comm.Type, parser.Comm.ClientID, parser.Comm.ServiceID, parser.Comm.Verifier)
	fmt.Printf("%s\n", parser.API.Data)

	verifyRespComm(parser, proto.MsgAuthTicketReq, keyring.ID, proto.AuthServiceID, ts)

	//if msgResp, err = proto.ParseAuthGetTicketResp(body, []byte(keyring.Key)); err != nil {
	//	panic(err)
	//}

	ticketfile.Ticket = parser.Ticket.Ticket
	ticketfile.Key = parser.Ticket.SessionKey
	ticketfile.ID = keyring.ID

	return
}

func getTicket() (err error) {
	cfg := config.LoadConfigFile(flaginfo.ticket.key)
	keyring := keyRing{
		ID:  cfg.GetString("id"),
		Key: cfg.GetString("key"),
	}

	ticketfile := getTicketFromAuth(&keyring)
	ticketfile.dump(flaginfo.ticket.output)

	return
}

func accessAuthServer() {
	var (
		msg        proto.MsgType
		sessionKey []byte
		err        error
		message    interface{}
		//data       []byte
		ts int64
	)

	switch flaginfo.api.request {
	case "createuser":
		msg = proto.MsgAuthCreateUserReq
	case "deleteuser":
		msg = proto.MsgAuthDeleteUserReq
	case "getuser":
		msg = proto.MsgAuthGetUserReq
	case "addcaps":
		msg = proto.MsgAuthAddCapsReq
	case "deletecaps":
		msg = proto.MsgAuthDeleteCapsReq
	case "getcaps":
		msg = proto.MsgAuthGetCapsReq
	default:
		panic(fmt.Errorf("wrong requst [%s]", flaginfo.api.request))
	}

	ticketCFG := config.LoadConfigFile(flaginfo.api.ticket)

	apiReq := &proto.APIAccessReq{
		Type:      msg,
		ClientID:  ticketCFG.GetString("id"),
		ServiceID: proto.AuthServiceID,
	}

	if sessionKey, err = cryptoutil.Base64Decode(ticketCFG.GetString("key")); err != nil {
		panic(err)
	}

	if apiReq.Verifier, ts, err = genVerifier(sessionKey); err != nil {
		panic(err)
	}
	apiReq.Ticket = ticketCFG.GetString("ticket")

	dataCFG := config.LoadConfigFile(flaginfo.api.data)

	switch flaginfo.api.request {
	case "createuser":
		message = proto.AuthCreateUserReq{
			APIReq: *apiReq,
			UserInfo: keystore.UserInfo{
				ID:   dataCFG.GetString("id"),
				Key:  []byte(""),
				Role: dataCFG.GetString("role"),
				Caps: []byte(dataCFG.GetString("caps")),
			},
		}
	case "deleteuser":
		message = proto.AuthDeleteUserReq{
			APIReq: *apiReq,
			ID:     dataCFG.GetString("id"),
		}
	case "getuser":
		message = proto.AuthGetUserReq{
			APIReq: *apiReq,
			ID:     dataCFG.GetString("id"),
		}
	case "addcaps":
		message = proto.AuthAddCapsReq{
			APIReq: *apiReq,
			ID:     dataCFG.GetString("id"),
			Caps:   []byte(dataCFG.GetString("caps")),
		}
	case "deletecaps":
		message = proto.AuthDeleteCapsReq{
			APIReq: *apiReq,
			ID:     dataCFG.GetString("id"),
			Caps:   []byte(dataCFG.GetString("caps")),
		}
	case "getcaps":
		message = proto.AuthGetCapsReq{
			APIReq: *apiReq,
			ID:     dataCFG.GetString("id"),
		}
	default:
		panic(fmt.Errorf("wrong action [%s]", flaginfo.api.request))
	}

	body := sendReq(flaginfo.api.url, message)

	var parser *proto.SecRespParser
	parser, err = proto.CreateSecRespParser(body, sessionKey)
	if err != nil {
		panic(err)
	}

	verifyRespComm(parser, msg, ticketCFG.GetString("id"), proto.AuthServiceID, ts)

	fmt.Printf("%d %s %s %d\n", parser.Comm.Type, parser.Comm.ClientID, parser.Comm.ServiceID, parser.Comm.Verifier)
	fmt.Printf("%s\n", parser.API.Data)
}

func verifyRespComm(parser *proto.SecRespParser, msg proto.MsgType, clientID string, serviceID string, ts int64) {
	if ts+1 != parser.Comm.Verifier {
		panic("verifier verification failed")
	}

	if parser.Comm.Type != msg+1 {
		panic("msg verification failed")
	}

	if parser.Comm.ClientID != clientID {
		panic("id verification failed")
	}

	if parser.Comm.ServiceID != serviceID {
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
		file := ticketCmd.String("output", "", "path to ticket file")
		ticketCmd.Parse(os.Args[2:])
		flaginfo.ticket.key = *key
		flaginfo.ticket.url = *url
		flaginfo.ticket.output = *file
		getTicket()
	} else {
		ticket := apiCmd.String("ticketfile", "dddd", "path to ticket file")
		url := apiCmd.String("url", "", "api url")
		data := apiCmd.String("data", "", "request data file")
		apiCmd.Parse(os.Args[2:])
		flaginfo.api.ticket = *ticket
		flaginfo.api.url = *url
		flaginfo.api.data = *data
		if len(apiCmd.Args()) >= 2 {
			flaginfo.api.service = apiCmd.Args()[0]
			flaginfo.api.request = apiCmd.Args()[1]
		} else {
			panic(fmt.Errorf("requst parameter needed"))
		}
		accessAPI()
	}
}
