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
	ospf.IntfConfMap[key] = intf
	ospf.processGlobalConfig(gConf)
	ospf.InitNeighborStateMachine()
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
		ospf.lsdbStateRefresh()
	case 3:
		fmt.Println(tNum, ": Running processRecvdRouterLsa ")
		ospf.initLSDatabase(lsdbKey.AreaId)
		ospf.processRecvdRouterLsa(lsa_router, lsdbKey.AreaId)
		ospf.processRecvdLsa(lsa_router, lsdbKey.AreaId)
		ospf.processRecvdLsa(lsa_fake, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_router, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_fake, lsdbKey.AreaId)
		ospf.lsdbStateRefresh()
	case 4:
		fmt.Println(tNum, ": Running processRecvdNetworkLsa")
		ospf.initLSDatabase(lsdbKey.AreaId)

		ospf.processRecvdNetworkLsa(lsa_network, lsdbKey.AreaId)
		ospf.processRecvdLsa(lsa_network, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_network, lsdbKey.AreaId)
		ospf.lsdbStateRefresh()
	case 5:
		fmt.Println(tNum, ": Running processRecvdSummaryLsa ")
		ospf.initLSDatabase(lsdbKey.AreaId)
		ospf.processRecvdSummaryLsa(lsa_summary, lsdbKey.AreaId, Summary3LSA)
		ospf.processRecvdLsa(lsa_summary, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_summary, lsdbKey.AreaId)
		ospf.lsdbStateRefresh()
	case 6:
		fmt.Println(tNum, ": Running processRecvdASExternalLsa ")
		ospf.initLSDatabase(lsdbKey.AreaId)
		ospf.processRecvdASExternalLsa(lsa_asExt, lsdbKey.AreaId)
		ospf.processRecvdLsa(lsa_asExt, lsdbKey.AreaId)
		ospf.processDeleteLsa(lsa_asExt, lsdbKey.AreaId)
		ospf.lsdbStateRefresh()

	case 7:
		fmt.Println(tNum, ": Running processLSDatabaseUpdates")
		checkLSDatabaseUpdates()
		ospf.lsdbStateRefresh()

	case 8:
		fmt.Println(tNum, ": Running LSAPKT tests ")
		checkLsaPktApis()
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
	ospf.processInterfaceChangeMsg(msg)

	nbrMdata := newospfNbrMdata()
	nbrMdata.areaId = lsdbKey.AreaId
	nbrMdata.intf = key
	nbrMdata.isDR = true
	nbrMdata.nbrList = nil
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

func checkLsaPktApis() {

	lsaHeader := getLsaHeaderFromLsa(routerLsa.LsaMd.LSAge, routerLsa.LsaMd.Options, routerKey.LSType,
		routerKey.LSId, routerKey.AdvRouter, uint32(routerLsa.LsaMd.LSSequenceNum),
		routerLsa.LsaMd.LSChecksum, routerLsa.LsaMd.LSLen)
	fmt.Println("Decoded LSA header ", lsaHeader)
	lsaDecode := decodeLSAReq(lsareq)
	fmt.Println("Decoded LSA req ", lsaDecode)
	decodeLSAReqPkt(lsa_router, uint16(len(lsa_router)))

	/* LSA req */
	encodeLSAReq(lsa_reqs)
	lsaPkt := ospf.EncodeLSAReqPkt(key, intf, nbrConf, lsa_reqs, dstMAC)
	fmt.Println("Encoded LSA packet ", lsaPkt)
	nbr_req = &ospfNeighborReq{}
	nbr_req.lsa_headers = lsaHeader
	nbr_req.valid = true
	nbr_req_list = []*ospfNeighborReq{}
	nbr_req_list = append(nbr_req_list, nbr_req)
	ospfNeighborRequest_list[nbrKey] = nbr_req_list
	index := ospf.BuildAndSendLSAReq(nbrKey, nbrConf)
	fmt.Println("Nbr lsa req list index ", index)

	lsaPkt = ospf.BuildLsaUpdPkt(key, intf, dstMAC, dstIP, len(lsa_router), lsa_router) 
	fmt.Println("Encoded LSA pkt :", lsaPkt)
	
	err := ospf.ProcessRxLsaUpdPkt(lsa_router, &ospfHdrMd, &ipHdrMd, key)
	if err != nil {
		fmt.Println("Failed to process received Rx LSA packet.", err)
	}
	
	/* LSA upd */
	lsaupd_msg := ospfNeighborLSAUpdMsg{
		nbrKey: nbrKey,
		data: lsa_update,
		areaId:lsdbKey.AreaId,
	}

nbrConf.OspfNbrState = config.NbrFull
ospf.NeighborConfigMap[nbrKey] = nbrConf

	ospf.DecodeLSAUpd(lsaupd_msg)

ospf.selfGenLsaCheck(routerKey)
ospf.lsaUpdDiscardCheck(nbrConf, lsa_router)

/* LSA ack */
lsaAck  := ospf.BuildLSAAckPkt(key, intf, nbrConf, dstMAC, dstIP, len(lsaack), lsaack)
fmt.Println("Encoded lsa ack packet ", lsaAck)

ospf.ProcessRxLSAAckPkt(lsaack, &ospfHdrMd, &ipHdrMd, key)
lsa_headers := []ospfLSAHeader{}
lsa_headers = append(lsa_headers, lsaHeader)
  lsaHeader = getLsaHeaderFromLsa(routerLsa.LsaMd.LSAge, routerLsa.LsaMd.Options, NetworkLSA,
                routerKey.LSId, routerKey.AdvRouter, uint32(routerLsa.LsaMd.LSSequenceNum),
                routerLsa.LsaMd.LSChecksum, routerLsa.LsaMd.LSLen)
lsa_headers = append(lsa_headers, lsaHeader)
ack_msg.lsa_headers = lsa_headers
ack_msg.nbrKey = nbrKey

ospf.DecodeLSAAck(*ack_msg)

/* LSA req */
ospfHdrMd.pktlen = uint16(len(lsareq) + OSPF_HEADER_SIZE)
err = ospf.ProcessRxLSAReqPkt(lsareq, &ospfHdrMd, &ipHdrMd, key)
if err != nil {
	fmt.Println("Failed to process rx LSA req pkt ", err)
	}
nbrConf.OspfNbrState = config.NbrFull
ospf.DecodeLSAReq(nbrLsaReqMsg)
ospf.generateLsaUpdUnicast(req, nbrKey, lsdbKey.AreaId)
req.ls_type = uint32(NetworkLSA)
ospf.generateLsaUpdUnicast(req, nbrKey, lsdbKey.AreaId)
req.ls_type = uint32(Summary4LSA)
ospf.generateLsaUpdUnicast(req, nbrKey, lsdbKey.AreaId)
req.ls_type = uint32(Summary3LSA)
ospf.generateLsaUpdUnicast(req, nbrKey, lsdbKey.AreaId)
req.ls_type = uint32(ASExternalLSA)
ospf.generateLsaUpdUnicast(req, nbrKey, lsdbKey.AreaId)
req.ls_type = uint32(10) //fake type
ospf.generateLsaUpdUnicast(req, nbrKey, lsdbKey.AreaId)

discard := ospf.lsaReqPacketDiscardCheck(nbrConf, req)
if discard {
	fmt.Println("Discard this packet ")
	}
discard = ospf.lsaAckPacketDiscardCheck(nbrConf)
	
/* LSA sanity checks */
discard = ospf.lsaAddCheck(lsaHeader, nbrConf)

ospf.lsaReTxTimerCheck(nbrKey)



}
