//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
// _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//
package server

import (
	_ "fmt"
	"l3/ndp/config"
	_ "l3/ndp/debug"
)

func (svr *NDPServer) GetNeighborEntries(idx, cnt int) (int, int, []config.NeighborConfig) {
	var nextIdx int
	var count int
	var i, j int

	length := len(svr.neighborKey)
	if length == 0 {
		return 0, 0, nil
	}
	var result []config.NeighborConfig

	svr.NeigborEntryLock.RLock()
	for i, j = 0, idx; i < cnt && j < length; j++ {
		key := svr.neighborKey[j]
		result = append(result, svr.NeighborInfo[key])
		i++
	}
	svr.NeigborEntryLock.RUnlock()
	if j == length {
		nextIdx = 0
	}
	count = i
	return nextIdx, count, result
}

func (svr *NDPServer) GetNeighborEntry(ipAddr string) *config.NeighborConfig {
	svr.NeigborEntryLock.RLock()
	defer svr.NeigborEntryLock.RUnlock()

	nbrEntry, exists := svr.NeighborInfo[ipAddr]
	if exists {
		return &nbrEntry
	}
	return nil
}
