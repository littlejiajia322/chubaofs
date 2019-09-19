package authnode

import (
  "fmt"
)

type UserInfo struct {
  Key string
  Caps []byte
}

var keystore = map[string]UserInfo{
	"client1": {
    Key:"11111111111111111111111111111111",
    Caps:[]byte(`{"apis": ["mount"]`),
    }, 
	"MasterService": {
    Key:"22222222222222222222222222222222",
    Caps:[]byte(`{}`),
  },
  "Admin":  {
    Key:"33333333333333333333333333333333",
    Caps:[]byte(`{"apis": ["*"]}`),
  },
}

// RetrieveUserInfo return the key according to user ID
func RetrieveUserInfo(name string) (userInfo UserInfo, err error) {
  if _, ok := keystore[name]; !ok {
    err = fmt.Errorf("user name %s is not existed in system", name)
    return
  }
  userInfo = keystore[name]
	return
}
/*
// SetuserKey return the key according to user ID
func SetUserKey(id string, key string) {
	keymap[id] = key
	return
}*/