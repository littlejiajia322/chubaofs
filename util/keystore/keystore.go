package keystore

import (
	"fmt"
	
	"github.com/chubaofs/chubaofs/util/cryptoutil"
)

type UserInfo struct {
	UserName string
	Key      string
	Role     string
	Caps     []byte
}

var keystore = map[string]UserInfo{
	"client1": {
		Key:  "11111111111111111111111111111111",
		Role: "client",
		Caps: []byte(`{"apis": ["mount"]`),
	},
	"MasterService": {
		Key:  "22222222222222222222222222222222",
		Role: "service",
		Caps: []byte(`{}`),
	},
	"admin": {
		Key:  "33333333333333333333333333333333",
		Role: "admin",
		Caps: []byte(`{"apis": ["*"]}`),
	},
}

var AuthMasterKey = "44444444444444444444444444444444"

// RetrieveUserInfo return the key according to user ID from keystore
func RetrieveUserInfo(name string) (userInfo UserInfo, err error) {
	if _, ok := keystore[name]; !ok {
		err = fmt.Errorf("user name [%s] is not existed in system", name)
		return
	}
	userInfo = keystore[name]
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
	res.Key = cryptoutil.Base64Encode(genClientMasterKey(userInfo.UserName))
	keystore[name] = res
	return
}

/*
// SetuserKey return the key according to user ID
func SetUserKey(id string, key string) {
	keymap[id] = key
	return
}*/
