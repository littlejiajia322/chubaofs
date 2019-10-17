package keystore

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/chubaofs/chubaofs/util/caps"
)

var roleSet = map[string]bool{
	"client":  true,
	"service": true,
}

// KeyInfo defines the key info structure in key store
type KeyInfo struct {
	ID   string `json:"id"`
	Key  []byte `json:"key"`
	Ts   int64  `json:"create_ts"`
	Role string `json:"role"`
	Caps []byte `json:"caps"`
}

// DumpJSONFile dump KeyInfo to file in json format
func (u *KeyInfo) DumpJSONFile(filename string) (err error) {
	var (
		data string
	)
	if data, err = u.DumpJSONStr(); err != nil {
		return
	}

	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()

	_, err = io.WriteString(file, data)
	if err != nil {
		return
	}
	return
}

// DumpJSONStr dump KeyInfo to string in json format
func (u *KeyInfo) DumpJSONStr() (r string, err error) {
	dumpInfo := struct {
		ID   string `json:"id"`
		Key  []byte `json:"key"`
		Ts   int64  `json:"create_ts"`
		Role string `json:"role"`
		Caps string `json:"caps"`
	}{
		u.ID,
		u.Key,
		u.Ts,
		u.Role,
		string(u.Caps),
	}
	data, err := json.MarshalIndent(dumpInfo, "", "  ")
	if err != nil {
		return
	}
	r = string(data)
	return
}

// IsValidID check the validity of ID
func (u *KeyInfo) IsValidID() (err error) {
	re := regexp.MustCompile("^[A-Za-z]{1,1}[A-Za-z0-9_]{0,20}$")
	if !re.MatchString(u.ID) {
		err = fmt.Errorf("invalid ID [%s]", u.ID)
		return
	}
	return
}

// IsValidRole check the validity of role
func (u *KeyInfo) IsValidRole() (err error) {
	if _, ok := roleSet[u.Role]; !ok {
		err = fmt.Errorf("invalid Role [%s]", u.Role)
		return
	}
	return
}

// IsValidCaps check the validity of caps
func (u *KeyInfo) IsValidCaps() (err error) {
	cap := new(caps.Caps)
	if err = cap.Init(u.Caps); err != nil {
		err = fmt.Errorf("Invalid caps [%s] %s", u.Caps, err.Error())
	}
	return
}

// IsValidKeyInfo is a valid of KeyInfo
func (u *KeyInfo) IsValidKeyInfo() (err error) {
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

/*
type keystore struct {
	Content map[string]KeyInfo
}

// Keystore in memory storage
var Keystore = keystore{
	Content: map[string]KeyInfo{
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

func (m *keystore) getValue(id string) (info KeyInfo, err error) {
	if _, ok := m.Content[id]; !ok {
		err = fmt.Errorf("ID [%s] is not existed in system", id)
		return
	}
	info = m.Content[id]
	return
}

func (m *keystore) addValue(id string, info *KeyInfo) (err error) {
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
	Keystore.Content[id] = KeyInfo{
		Key:  Keystore.Content[id].Key,
		Role: Keystore.Content[id].Role,
		Caps: caps,
	}
	return
}

// AuthMasterKey defines the Master key for Auth Service
var AuthMasterKey = []byte("44444444444444444444444444444444")

// GetKeyInfo return the key according to key ID from keystore
func GetKeyInfo(id string) (KeyInfo KeyInfo, err error) {
	if KeyInfo, err = Keystore.getValue(id); err != nil {
		return
	}
	return
}

// GetMasterKey return the master key from keystore according to key ID
func GetMasterKey(id string) (key []byte, err error) {
	var (
		KeyInfo KeyInfo
	)
	if KeyInfo, err = Keystore.getValue(id); err != nil {
		return
	}
	key = KeyInfo.Key
	return
}

// GetCaps return the capbility from keystore according to key ID
func GetCaps(id string) (caps []byte, err error) {
	var (
		KeyInfo KeyInfo
	)
	if KeyInfo, err = Keystore.getValue(id); err != nil {
		return
	}
	caps = KeyInfo.Caps
	return
}

// DeleteKey delete an key in Keystore
func DeleteKey(id string) (err error) {
	if err = Keystore.deleteValue(id); err != nil {
		return
	}
	return
}

// AddCaps add caps for existing key
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

// DeleteCaps add caps for existing key
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
*/
