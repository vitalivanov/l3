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
	"l3/ospf/config"
	"testing"
)

func initTestParams() {
	fmt.Println("\n Get Server object")
	ospf = getServerObject()
	initAttr()
	go startDummyChannels(ospf)
}

func TestOspfIntfFSM(t *testing.T) {
	fmt.Println("**************** INTF FSM ************")
	initTestParams()
	for index := 1; index < 11; index++ {
		err := intfFSMTestLogic(index)
		if err != SUCCESS {
			fmt.Println("Failed test case for interface FSM")
		}
	}
}

func intfFSMTestLogic(tNum int) int {
	ospf.initDefaultIntfConf(key, ipIntfProp, ifType)
	switch tNum {
	case 1:
		fmt.Println(tNum, ": Running StartOspfIntfFSM")
		ospf.StartOspfIntfFSM(key)

	case 2:
		fmt.Println(tNum, ": Running StartOspfP2PIntfFSM")
		//	ospf.StartOspfP2PIntfFSM(key)

	case 3:
		fmt.Println(tNum, ": Running processNbrDownEvent")
		ospf.processNbrDownEvent(msg, key, false) // broadcast network

	case 4:
		fmt.Println(tNum, ": Running processNbrFullStateMsg")
		ospf.processNbrFullStateMsg(msgNbrFull, key)

	case 5:
		fmt.Println(tNum, ": Running ElectBDR")
		electedBDR, electedRtrId := ospf.ElectBDR(key)
		fmt.Println("Elected BDR ", electedBDR, " electedRtrId ", electedRtrId)

	case 6:
		fmt.Println(tNum, ": Running ElectDR")
		BDR := []byte{10, 1, 1, 2}
		RtrIdBDR := uint32(2)
		dr, drid := ospf.ElectDR(key, BDR, RtrIdBDR)
		fmt.Println("Elected DR ", dr, " Router id ", drid)

	case 7:
		fmt.Println(tNum, ": Running ElectBDRAndDR")
		ospf.IntfConfMap[key] = intf
		ospf.ElectBDRAndDR(key)

	case 8:
		fmt.Println(tNum, ": Running createAndSendEventsIntfFSM")
		oldState := config.Down
		newState := config.DesignatedRouter
		oldRtr := uint32(2)
		oldBdr := uint32(10)
		ospf.createAndSendEventsIntfFSM(key, oldState, newState, oldRtr, oldBdr)

	case 9:
		fmt.Println(tNum, ": Running StopOspfIntfFSM")
		//	ospf.StopOspfIntfFSM(key)
	}
	return SUCCESS
}
