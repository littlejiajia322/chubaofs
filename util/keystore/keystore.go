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
	ID   string `json:"id"`
	Key  []byte `json:"key"`
	Role string `json:"role"`
	Caps []byte `json:"caps"`
}

// Dump dump UserInfo
func (u *UserInfo) Dump() (d string, err error) {
	var (
		caps caps.Caps
	)

	if err = json.Unmarshal(u.Caps, &caps); err != nil {
		return
	}

	d = fmt.Sprintf("ID:%s\nKey:%s\nRole:%s\nCaps:%s\n", u.ID, cryptoutil.Base64Encode(u.Key), u.Role, caps.Dump())
	return
}

// IsValidID check the validity of ID
func (u *UserInfo) IsValidID() (err error) {
	re := regexp.MustCompile("^[A-Za-z]{1,1}[A-Za-z0-9_]{0,11}$")
	if !re.MatchString(u.ID) {
		err = fmt.Errorf("invalid ID [%s]", u.ID)
		return
	}
	return
}

// IsValidRole check the validity of role
func (u *UserInfo) IsValidRole() (err error) {
	if _, ok := roleSet[u.Role]; !ok {
		err = fmt.Errorf("invalid Role [%s]", u.Role)
		return
	}
	return
}

// IsValidCaps check the validity of caps
func (u *UserInfo) IsValidCaps() (err error) {
	cap := new(caps.Caps)
	if err = cap.Init(u.Caps); err != nil {
		err = fmt.Errorf("Invalid caps [%s] %s", u.Caps, err.Error())
	}
	return
}

// IsValidFormat is a valid of UserInfo
func (u *UserInfo) IsValidUserInfo() (err error) {
	if err = u.IsValidID(); err != nil {
		return
	}
	if err = u.IsValidRole(); err != nil {
		return
	}
	if err = u.IsValidCaps(); err != nil {
		return
	}
	return
}

type keystore struct {
	Content map[string]UserInfo
}

// Keystore in memory storage
var Keystore = keystore{
	Content: map[string]UserInfo{
		"client1": {
			ID:   "client1",
			Key:  []byte("11111111111111111111111111111111"),
			Role: "client",
			Caps: []byte(`{"API": ["mount"]`),
		},
		"MasterService": {
			ID:   "MasterService",
			Key:  []byte("22222222222222222222222222222222"),
			Role: "service",
			Caps: []byte(`{}`),
		},
		"admin": {
			ID:   "admin",
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

func (m *keystore) deleteValue(id string) (err error) {
	if _, ok := m.Content[id]; !ok {
		err = fmt.Errorf("ID [%s] is not existed in system", id)
		return
	}
	delete(m.Content, id)
	return
}

func (m *keystore) updateCaps(id string, caps []byte) (err error) {
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

// GetUserInfo return the key according to user ID from keystore
func GetUserInfo(id string) (userInfo UserInfo, err error) {
	if userInfo, err = Keystore.getValue(id); err != nil {
		return
	}
	return
}

// GetMasterKey return the master key from keystore according to user ID
func GetMasterKey(id string) (key []byte, err error) {
	var (
		userInfo UserInfo
	)
	if userInfo, err = Keystore.getValue(id); err != nil {
		return
	}
	key = userInfo.Key
	return
}

// GetCaps return the capbility from keystore according to user ID
func GetCaps(id string) (caps []byte, err error) {
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
	if err = Keystore.addValue(id, &res); err != nil {
		return
	}
	return
}

// DeleteUser delete an user in Keystore
func DeleteUser(id string) (err error) {
	if err = Keystore.deleteValue(id); err != nil {
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
	if cur, err = GetCaps(id); err != nil {
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
	Keystore.updateCaps(id, newCaps)
	return
}

// DeleteCaps add caps for existing user
func DeleteCaps(id string, del []byte) (newCaps []byte, err error) {
	var (
		cur []byte
	)

	delCaps := new(caps.Caps)
	if err = delCaps.Init(del); err != nil {
		return
	}
	if cur, err = GetCaps(id); err != nil {
		return
	}
	curCaps := new(caps.Caps)
	if err = curCaps.Init(cur); err != nil {
		return
	}

	curCaps.Delete(delCaps)

	if newCaps, err = json.Marshal(curCaps); err != nil {
		return
	}
	Keystore.updateCaps(id, newCaps)
	return
}

func genClientMasterKey(name string) (key []byte) {
	// generate client master key according to ID and AuthMasterkey
	key = cryptoutil.GenMasterKey([]byte(AuthMasterKey), []byte(name))
	return
}
