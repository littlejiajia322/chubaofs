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

package master

import (
	"fmt"
	"github.com/chubaofs/chubaofs/proto"
	"github.com/chubaofs/chubaofs/util/errors"
	"sort"
)

type weightedNode struct {
	Carry  float64
	Weight float64
	Ptr    Node
	ID     uint64
}

// Node defines an interface that needs to be implemented by weightedNode
type Node interface {
	SetCarry(carry float64)
	SelectNodeForWrite()
}

// SortedWeightedNodes defines an array sorted by carry
type SortedWeightedNodes []*weightedNode

func (nodes SortedWeightedNodes) Len() int {
	return len(nodes)
}

func (nodes SortedWeightedNodes) Less(i, j int) bool {
	return nodes[i].Carry > nodes[j].Carry
}

func (nodes SortedWeightedNodes) Swap(i, j int) {
	nodes[i], nodes[j] = nodes[j], nodes[i]
}

func (nodes SortedWeightedNodes) setNodeCarry(availCarryCount, replicaNum int) {
	if availCarryCount >= replicaNum {
		return
	}
	for availCarryCount < replicaNum {
		availCarryCount = 0
		for _, nt := range nodes {
			carry := nt.Carry + nt.Weight
			if carry > 10.0 {
				carry = 10.0
			}
			nt.Carry = carry
			nt.Ptr.SetCarry(carry)
			if carry > 1.0 {
				availCarryCount++
			}
		}
	}
}

func (ns *nodeSet) getMetaNodeMaxTotal() (maxTotal uint64) {
	ns.metaNodes.Range(func(key, value interface{}) bool {
		metaNode := value.(*MetaNode)
		if metaNode.Total > maxTotal {
			maxTotal = metaNode.Total
		}
		return true
	})
	return
}

func (ns *nodeSet) getAvailMetaNodeHosts(excludeHosts []string, replicaNum int) (newHosts []string, peers []proto.Peer, err error) {
	orderHosts := make([]string, 0)
	newHosts = make([]string, 0)
	peers = make([]proto.Peer, 0)
	if replicaNum == 0 {
		return
	}

	maxTotal := ns.getMetaNodeMaxTotal()
	nodes, count := ns.getAllCarryNodes(maxTotal, excludeHosts)
	if len(nodes) < replicaNum {
		err = fmt.Errorf(getAvailMetaNodeHostsErr+" err:%v ,ActiveNodeCount:%v  MatchNodeCount:%v  ",
			errors.ErrNoMetaNodeToWrite, ns.metaNodeLen, len(nodes))
		return
	}

	nodes.setNodeCarry(count, replicaNum)
	sort.Sort(nodes)

	for i := 0; i < replicaNum; i++ {
		node := nodes[i].Ptr.(*MetaNode)
		node.SelectNodeForWrite()
		orderHosts = append(orderHosts, node.Addr)
		peer := proto.Peer{ID: node.ID, Addr: node.Addr}
		peers = append(peers, peer)
	}

	if newHosts, err = reshuffleHosts(orderHosts); err != nil {
		err = fmt.Errorf(getAvailMetaNodeHostsErr+"err:%v  orderHosts is nil", err.Error())
		return
	}
	return
}

func (ns *nodeSet) getAllCarryNodes(maxTotal uint64, excludeHosts []string) (nodes SortedWeightedNodes, availCount int) {
	nodes = make(SortedWeightedNodes, 0)
	ns.metaNodes.Range(func(key, value interface{}) bool {
		metaNode := value.(*MetaNode)
		if contains(excludeHosts, metaNode.Addr) == true {
			return true
		}
		if metaNode.isWritable() == false {
			return true
		}
		if metaNode.isCarryNode() == true {
			availCount++
		}
		nt := new(weightedNode)
		nt.Carry = metaNode.Carry
		if metaNode.Used < 0 {
			nt.Weight = 1.0
		} else {
			nt.Weight = (float64)(maxTotal-metaNode.Used) / (float64)(maxTotal)
		}
		nt.Ptr = metaNode
		nodes = append(nodes, nt)

		return true
	})

	return
}
