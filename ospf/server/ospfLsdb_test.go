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

func initLsdbTestParams() {
	fmt.Println("\n Get Server object")
	ospf = getServerObject()
	initAttr()
	go startDummyChannels(ospf)
}

func TestOspfLsdb(t *testing.T) {
	fmt.Println("\n**************** LSDB ************\n")
	initLsdbTestParams()
	for index := 1; index < 21; index++ {
		err := lsdbTestLogic(index)
		if err != SUCCESS {
			fmt.Println("Failed test case for interface FSM")
		}
	}
}

func lsdbTestLogic(tNum int) int {
	areaId := uint32(2)
	switch tNum {
	case 1:
		fmt.Println(tNum, ": Running initLSDatabase ")
		ospf.initLSDatabase(areaId)

	case 2:
		fmt.Println(tNum, ": Running insertSummaryLsa ")
		ospf.initLSDatabase(lsdbKey.AreaId)
		ospf.insertSummaryLsa(lsdbKey, summaryKey, summaryLsa)

	case 3:
		fmt.Println(tNum, ": Running processRecvdRouterLsa ")
		ospf.initLSDatabase(lsdbKey.AreaId)
		ospf.processRecvdRouterLsa(lsa_router, lsdbKey.AreaId)
		ospf.processRecvdLsa(lsa_router, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_router, lsdbKey.AreaId)

	case 4:
		fmt.Println(tNum, ": Running processRecvdNetworkLsa")
		ospf.initLSDatabase(lsdbKey.AreaId)

		ospf.processRecvdNetworkLsa(lsa_network, lsdbKey.AreaId)
		ospf.processRecvdLsa(lsa_network, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_network, lsdbKey.AreaId)

	case 5:
		fmt.Println(tNum, ": Running processRecvdSummaryLsa ")
		ospf.initLSDatabase(lsdbKey.AreaId)
		ospf.processRecvdSummaryLsa(lsa_summary, lsdbKey.AreaId, Summary3LSA)
		ospf.processRecvdLsa(lsa_summary, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_summary, lsdbKey.AreaId)

	case 6:
		fmt.Println(tNum, ": Running processRecvdASExternalLsa ")
		ospf.initLSDatabase(lsdbKey.AreaId)
		ospf.processRecvdASExternalLsa(lsa_asExt, lsdbKey.AreaId)
		ospf.processRecvdLsa(lsa_asExt, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_asExt, lsdbKey.AreaId)

	case 7:
		fmt.Println(tNum, ": Running processLSDatabaseUpdates")
		checkLSDatabaseUpdates()

	}

	return SUCCESS

}

func checkLSDatabaseUpdates() {
	ospf.StartLSDatabase()
	ospf.initLSDatabase(lsdbKey.AreaId)
	lsdb_msg := NewLsdbUpdateMsg()
	lsdb_msg.AreaId = lsdbKey.AreaId
	lsdb_msg.Data = make([]byte, len(lsa_router))
	copy(lsdb_msg.Data, lsa_router)
	lsdb_msg.MsgType = LsdbAdd

	ospf.LsdbUpdateCh <- *lsdb_msg

	lsdb_msg.MsgType = LsdbDel
	ospf.LsdbUpdateCh <- *lsdb_msg
	lsdb_msg.MsgType = LsdbUpdate
	ospf.LsdbUpdateCh <- *lsdb_msg
	ospf.ospfGlobalConf.AreaBdrRtrStatus = true
	msg := NetworkLSAChangeMsg{
		areaId:  lsdbKey.AreaId,
		intfKey: key,
	}
	ospf.IntfStateChangeCh <- msg

	nbrMdata := newospfNbrMdata()
	nbrMdata.areaId = lsdbKey.AreaId
	nbrMdata.intf = key
	nbrMdata.isDR = true
	nbrMdata.nbrList = nil
	ospf.IntfConfMap[key] = intf
	/* CHECK why blocked */
	//ospf.CreateNetworkLSACh <- *nbrMdata
	ospf.processNeighborFullEvent(*nbrMdata)

	msg1 := DrChangeMsg{
		areaId:   lsdbKey.AreaId,
		intfKey:  key,
		oldstate: config.OtherDesignatedRouter,
		newstate: config.BackupDesignatedRouter,
	}
	//ospf.NetworkDRChangeCh <- msg1
	ospf.processDrBdrChangeMsg(msg1)

	routemdata := RouteMdata{
		ipaddr: 2,
		mask:   100,
		metric: 10,
		isDel:  false,
	}
	//	ospf.ExternalRouteNotif <- routemdata
	ospf.processExtRouteUpd(routemdata)

	msg2 := maxAgeLsaMsg{
		lsaKey:   summaryKey,
		msg_type: delMaxAgeLsa,
	}
	//	ospf.maxAgeLsaCh <- msg2
	ospf.processMaxAgeLsaMsg(msg2)
}
