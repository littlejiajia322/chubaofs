package keystore

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/chubaofs/chubaofs/util/caps"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
)

var roleSet = map[string]bool{
	"client":  true,
	"service": true,
}

// UserInfo defines the user info structure in key store
type UserInfo struct {
	UserName string
	Key      []byte
	Role     string
	Caps     []byte
}

func (u *UserInfo) Dump() {
	var (
		caps caps.Caps
	)

	if err := json.Unmarshal(u.Caps, &caps); err != nil {
		panic(err)
	}

	println("UserName:\t", u.UserName)
	println("Key:\t", cryptoutil.Base64Encode(u.Key))
	println("Role:\t", u.Role)
	print("Caps:\t")
	caps.DumpCaps()
}

// IsValidFormat is a valid of UserInfo
func (u *UserInfo) IsValidFormat() (err error) {
	re := regexp.MustCompile("^[A-Za-z]{1,1}[A-Za-z0-9_]{0,11}$")
	if !re.MatchString(u.UserName) {
		err = fmt.Errorf("UserName invalid format %s", u.UserName)
		return
	}

	if _, ok := roleSet[u.Role]; !ok {
		err = fmt.Errorf("Role invalid [%s]", u.Role)
		return
	}

	cap := new(caps.Caps)
	if err = cap.Init(u.Caps); err != nil {
		return
	}

	return
}

var keystore = map[string]UserInfo{
	"client1": {
		Key:  []byte("11111111111111111111111111111111"),
		Role: "client",
		Caps: []byte(`{"API": ["mount"]`),
	},
	"MasterService": {
		Key:  []byte("22222222222222222222222222222222"),
		Role: "service",
		Caps: []byte(`{}`),
	},
	"admin": {
		Key:  []byte("33333333333333333333333333333333"),
		Role: "admin",
		Caps: []byte(`{"API": ["createuser"]}`),
	},
}

// AuthMasterKey defines the Master key for Auth Service
var AuthMasterKey = []byte("44444444444444444444444444444444")

// RetrieveUserInfo return the key according to user ID from keystore
func RetrieveUserInfo(name string) (userInfo UserInfo, err error) {
	if _, ok := keystore[name]; !ok {
		err = fmt.Errorf("user name [%s] is not existed in system", name)
		return
	}
	userInfo = keystore[name]
	return
}

// RetrieveUserMasterKey return the master key from keystore according to user ID
func RetrieveUserMasterKey(name string) (key []byte, err error) {
	if _, ok := keystore[name]; !ok {
		err = fmt.Errorf("user name [%s] is not existed in system", name)
		return
	}
	key = keystore[name].Key
	return
}

// RetrieveUserCapability return the capbility from keystore according to user ID
func RetrieveUserCapability(name string) (caps []byte, err error) {
	if _, ok := keystore[name]; !ok {
		err = fmt.Errorf("user name [%s] is not existed in system", name)
		return
	}
	caps = keystore[name].Caps
	return
}

func genClientMasterKey(name string) (key []byte) {
	// generate client master key according to username and AuthMasterkey
	key = cryptoutil.GenMasterKey([]byte(AuthMasterKey), []byte(name))
	return
}

// AddNewUser add a new user into keystore
func AddNewUser(name string, userInfo *UserInfo) (res UserInfo, err error) {
	if _, ok := keystore[name]; ok {
		err = fmt.Errorf("user name [%s] exisited in system", name)
		return
	}
	res = *userInfo
	res.Key = genClientMasterKey(userInfo.UserName)
	keystore[name] = res
	return
}
