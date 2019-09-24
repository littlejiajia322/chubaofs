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
	ID   string
	Key  []byte
	Role string
	Caps []byte
}

func (u *UserInfo) Dump() {
	var (
		caps caps.Caps
	)

	if err := json.Unmarshal(u.Caps, &caps); err != nil {
		panic(err)
	}

	println("ID:\t", u.ID)
	println("Key:\t", cryptoutil.Base64Encode(u.Key))
	println("Role:\t", u.Role)
	print("Caps:\t")
	caps.DumpCaps()
}

// IsValidFormat is a valid of UserInfo
func (u *UserInfo) IsValidFormat() (err error) {
	re := regexp.MustCompile("^[A-Za-z]{1,1}[A-Za-z0-9_]{0,11}$")
	if !re.MatchString(u.ID) {
		err = fmt.Errorf("ID invalid format %s", u.ID)
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

type keystore struct {
	Content map[string]UserInfo
}

var Keystore = keystore{
	Content: map[string]UserInfo{
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
			Caps: []byte(`{"API": ["*"]}`),
		},
	},
}

func (m *keystore) getValue(id string) (info UserInfo, err error) {
	if _, ok := m.Content[id]; !ok {
		err = fmt.Errorf("ID [%s] is not existed in system", id)
		return
	}
	info = m.Content[id]
	return
}

func (m *keystore) addValue(id string, info *UserInfo) (err error) {
	if _, ok := m.Content[id]; ok {
		err = fmt.Errorf("ID [%s] is existed in system", id)
		return
	}
	Keystore.Content[id] = *info
	return
}

func (m *keystore) addCaps(id string, caps []byte) (err error) {
	if _, ok := m.Content[id]; !ok {
		err = fmt.Errorf("ID [%s] is not existed in system", id)
		return
	}
	Keystore.Content[id] = UserInfo{
		Key:  Keystore.Content[id].Key,
		Role: Keystore.Content[id].Role,
		Caps: caps,
	}
	return
}

// AuthMasterKey defines the Master key for Auth Service
var AuthMasterKey = []byte("44444444444444444444444444444444")

// RetrieveUserInfo return the key according to user ID from keystore
func RetrieveUserInfo(id string) (userInfo UserInfo, err error) {
	if userInfo, err = Keystore.getValue(id); err != nil {
		return
	}
	return
}

// RetrieveUserMasterKey return the master key from keystore according to user ID
func RetrieveUserMasterKey(id string) (key []byte, err error) {
	var (
		userInfo UserInfo
	)
	if userInfo, err = Keystore.getValue(id); err != nil {
		return
	}
	key = userInfo.Key
	return
}

// RetrieveUserCapability return the capbility from keystore according to user ID
func RetrieveUserCapability(id string) (caps []byte, err error) {
	var (
		userInfo UserInfo
	)
	if userInfo, err = Keystore.getValue(id); err != nil {
		return
	}
	caps = userInfo.Caps
	return
}

// AddNewUser add a new user into keystore
func AddNewUser(id string, userInfo *UserInfo) (res UserInfo, err error) {
	res = *userInfo
	res.Key = genClientMasterKey(userInfo.ID)
	if err = Keystore.addValue(id, userInfo); err != nil {
		return
	}
	return
}

// AddCaps add caps for existing user
func AddCaps(id string, add []byte) (newCaps []byte, err error) {
	var (
		cur []byte
	)

	addCaps := new(caps.Caps)
	if err = addCaps.Init(add); err != nil {
		return
	}
	if cur, err = RetrieveUserCapability(id); err != nil {
		return
	}
	curCaps := new(caps.Caps)
	if err = curCaps.Init(cur); err != nil {
		return
	}

	curCaps.Union(addCaps)

	if newCaps, err = json.Marshal(curCaps); err != nil {
		return
	}
	Keystore.addCaps(id, newCaps)
	return
}

func genClientMasterKey(name string) (key []byte) {
	// generate client master key according to ID and AuthMasterkey
	key = cryptoutil.GenMasterKey([]byte(AuthMasterKey), []byte(name))
	return
}
