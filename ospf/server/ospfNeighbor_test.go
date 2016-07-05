//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//       Unless required by applicable law or agreed to in writing, software
//       distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//       See the License for the specific language governing permissions and
//       limitations under the License.
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
	"fmt"
	"testing"
)

func initNbrTestParams() {
	fmt.Println("\n Get Server object")
	ospf = getServerObject()
	initAttr()
	go startDummyChannels(ospf)
	ospf.InitNeighborStateMachine()
}

func TestOspfNbrFSM(t *testing.T) {
	initNbrTestParams()
	for index := 1; index < 11; index++ {
		err := nbrFSMTestLogic(index)
		if err != SUCCESS {
			fmt.Println("Failed test case for interface FSM")
		}
	}
}

func nbrFSMTestLogic(tNum int) int {
	ospf.initDefaultIntfConf(key, ipIntfProp, ifType)
	switch tNum {
	case 1:
		fmt.Println(tNum, ": Running Neighbor create")
		ospf.IntfConfMap[key] = intf
		go ospf.UpdateNeighborConf()
		ospf.neighborConfCh <- nbrConfMsg
		ospf.neighborConfStopCh <- true

	case 2:
		fmt.Println(tNum, ": Running updateLSALists")
		updateLSALists(nbrKey)

	case 3:
		fmt.Println(tNum, ": Running initNeighborMdata")
		ospf.initNeighborMdata(key)

	case 4:
		fmt.Println(tNum, ": Running updateNeighborMdata")
		ospf.updateNeighborMdata(key, nbrKey)

	case 5:
		fmt.Println(tNum, ": Running resetNeighborLists")
		ospf.IntfConfMap[key] = intf
		ospf.resetNeighborLists(nbrKey, key)

	case 6:
		fmt.Println(tNum, ": Running UpdateNeighborList")
		ospf.IntfConfMap[key] = intf
		go ospf.UpdateNeighborConf()
		ospf.UpdateNeighborList(nbrKey)
		ospf.neighborConfStopCh <- true
	}
	return SUCCESS
}
