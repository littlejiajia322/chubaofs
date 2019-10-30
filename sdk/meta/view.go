// Copyright 2018 The Chubao Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package meta

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"github.com/chubaofs/chubaofs/util/log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const (
	MaxSendToMaster = 3
)

type VolumeView struct {
	VolName        string
	MetaPartitions []*MetaPartition
}

type VolStatInfo struct {
	Name      string
	TotalSize uint64
	UsedSize  uint64
}

// VolName view managements
//
func (mw *MetaWrapper) fetchVolumeView() (*VolumeView, error) {
	params := make(map[string]string)
	params["name"] = mw.volname
	authKey, err := calculateAuthKey(mw.owner)
	if err != nil {
		return nil, err
	}
	params["authKey"] = authKey
	mw.accessToken.Type = proto.MsgMasterFetchVolViewReq
	tokenMessage, err := genMasterToken(mw.accessToken, mw.sessionKey)
	if err != nil {
		log.LogWarnf("fetchVolumeView generate token failed: err(%v)", err)
		return nil, err
	}
	params["token"] = tokenMessage
	body, err := mw.master.Request(http.MethodPost, proto.ClientVol, params, nil)
	if err != nil {
		log.LogWarnf("fetchVolumeView request: err(%v)", err)
		return nil, err
	}

	view := new(VolumeView)
	if err = json.Unmarshal(body, view); err != nil {
		log.LogWarnf("fetchVolumeView unmarshal: err(%v) body(%v)", err, string(body))
		return nil, err
	}
	return view, nil
}

// fetch and update cluster info if successful
func (mw *MetaWrapper) updateClusterInfo() error {
	paras := make(map[string]string, 0)
	//TODO 需要验证response吗,ts
	mw.accessToken.Type = proto.MsgMasterUpdateClusterInfoReq
	tokenMessage, err := genMasterToken(mw.accessToken, mw.sessionKey)
	if err != nil {
		log.LogWarnf("updateClusterInfo generate token failed: err(%v)", err)
		return err
	}
	paras["token"] = tokenMessage
	body, err := mw.master.Request(http.MethodPost, proto.AdminGetIP, nil, nil)
	if err != nil {
		log.LogWarnf("updateClusterInfo request: err(%v)", err)
		return err
	}

	info := new(proto.ClusterInfo)
	if err = json.Unmarshal(body, info); err != nil {
		log.LogWarnf("updateClusterInfo unmarshal: err(%v)", err)
		return err
	}
	log.LogInfof("ClusterInfo: %v", *info)
	mw.cluster = info.Cluster
	mw.localIP = info.Ip
	return nil
}

func (mw *MetaWrapper) updateVolStatInfo() error {
	params := make(map[string]string)
	params["name"] = mw.volname
	mw.accessToken.Type = proto.MsgMasterUpdateVolStateInfoReq
	tokenMessage, err := genMasterToken(mw.accessToken, mw.sessionKey)
	if err != nil {
		log.LogWarnf("updateVolStatInfo generate token failed: err(%v)", err)
		return err
	}
	params["token"] = tokenMessage
	body, err := mw.master.Request(http.MethodPost, proto.ClientVolStat, params, nil)
	if err != nil {
		log.LogWarnf("updateVolStatInfo request: err(%v)", err)
		return err
	}

	info := new(VolStatInfo)
	if err = json.Unmarshal(body, info); err != nil {
		log.LogWarnf("updateVolStatInfo unmarshal: err(%v)", err)
		return err
	}
	atomic.StoreUint64(&mw.totalSize, info.TotalSize)
	atomic.StoreUint64(&mw.usedSize, info.UsedSize)
	log.LogInfof("VolStatInfo: info(%v)", *info)
	return nil
}

func (mw *MetaWrapper) updateMetaPartitions() error {
	view, err := mw.fetchVolumeView()
	if err != nil {
		return err
	}

	rwPartitions := make([]*MetaPartition, 0)
	for _, mp := range view.MetaPartitions {
		mw.replaceOrInsertPartition(mp)
		log.LogInfof("updateMetaPartition: mp(%v)", mp)
		if mp.Status == proto.ReadWrite {
			rwPartitions = append(rwPartitions, mp)
		}
	}

	if len(rwPartitions) == 0 {
		log.LogInfof("updateMetaPartition: no rw partitions")
		return nil
	}

	mw.Lock()
	mw.rwPartitions = rwPartitions
	mw.Unlock()
	return nil
}

func (mw *MetaWrapper) refresh() {
	t := time.NewTicker(RefreshMetaPartitionsInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			mw.updateMetaPartitions()
			mw.updateVolStatInfo()
		}
	}
}

func calculateAuthKey(key string) (authKey string, err error) {
	h := md5.New()
	_, err = h.Write([]byte(key))
	if err != nil {
		log.LogErrorf("action[calculateAuthKey] calculate auth key[%v] failed,err[%v]", key, err)
		return
	}
	cipherStr := h.Sum(nil)
	return strings.ToLower(hex.EncodeToString(cipherStr)), nil
}

func genMasterToken(req proto.APIAccessReq, key string) (message string, err error) {
	var (
		sessionKey []byte
		data       []byte
	)

	if sessionKey, err = cryptoutil.Base64Decode(key); err != nil {
		return
	}

	if req.Verifier, _, err = cryptoutil.GenVerifier(sessionKey); err != nil {
		return
	}

	if data, err = json.Marshal(req); err != nil {
		return
	}

	message = base64.StdEncoding.EncodeToString(data)

	return
}
