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
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"l3/ndp/config"
	"l3/ndp/debug"
	"l3/ndp/packet"
	_ "net"
)

/*
 *	Receive Ndp Packet
 */
func (svr *NDPServer) ReceivedNdpPkts(ifIndex int32) {
	ipPort, _ := svr.L3Port[ifIndex]
	if ipPort.PcapBase.PcapHandle == nil {
		debug.Logger.Err(fmt.Sprintln("pcap handler for port:", ipPort.IntfRef, "is not valid. ABORT!!!!"))
		return
	}
	src := gopacket.NewPacketSource(ipPort.PcapBase.PcapHandle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case pkt, ok := <-in:
			if !ok {
				continue
			}
			svr.RxPktCh <- &RxPktInfo{pkt, ipPort.IfIndex}
		case <-ipPort.PcapBase.PcapCtrl:
			svr.DeletePcapHandler(&ipPort.PcapBase.PcapHandle)
			svr.L3Port[ifIndex] = ipPort
			ipPort.PcapBase.PcapCtrl <- true
			return
		}
	}
}

/*
 *	StartRxTx      a) Check if entry is present in the map
 *		       b) If no entry create one do the initialization for the entry
 *		       c) Create Pcap Handler & add the entry to up interface slice
 *		       d) Start receiving Packets
 */
func (svr *NDPServer) StartRxTx(ifIndex int32) {
	ipPort, exists := svr.L3Port[ifIndex]
	if !exists {
		// This will copy msg (intRef, ifIndex, ipAddr) into ipPort
		// And also create an entry into the ndpL3IntfStateSlice
		debug.Logger.Err(fmt.Sprintln("Failed starting RX/TX for interface which was not created, ifIndex:",
			ifIndex, "is not allowed"))
		return
	}
	svr.L3Port[ifIndex] = ipPort
	// create pcap handler if there is none created right now
	if ipPort.PcapBase.PcapHandle == nil {
		var err error
		ipPort.PcapBase.PcapHandle, err = svr.CreatePcapHandler(ipPort.IntfRef)
		if err != nil {
			return
		}
		svr.L3Port[ifIndex] = ipPort
	}
	debug.Logger.Info(fmt.Sprintln("Start rx/tx for port:", ipPort.IntfRef, "ifIndex:", ipPort.IfIndex,
		"ip address", ipPort.IpAddr))

	// Spawn go routines for rx & tx
	go svr.ReceivedNdpPkts(ipPort.IfIndex)
	svr.ndpUpL3IntfStateSlice = append(svr.ndpUpL3IntfStateSlice, ifIndex)
	svr.Packet.SendNSMsgIfRequired(ipPort.IpAddr)
}

/*
 *	StopRxTx       a) Check if entry is present in the map
 *		       b) If present then send a ctrl signal to stop receiving packets
 *		       c) block until cleanup is going on
 *		       c) delete the entry from up interface slice
 */
func (svr *NDPServer) StopRxTx(ifIndex int32) {
	ipPort, exists := svr.L3Port[ifIndex]
	if !exists {
		debug.Logger.Err(fmt.Sprintln("No entry found for ifIndex:", ifIndex))
		return
	}
	// Blocking call until Pcap is deleted
	ipPort.PcapBase.PcapCtrl <- true
	<-ipPort.PcapBase.PcapCtrl
	debug.Logger.Info(fmt.Sprintln("Stop rx/tx for port:", ipPort.IntfRef, "ifIndex:", ipPort.IfIndex,
		"ip address", ipPort.IpAddr, "is done"))
	// Delete Entry from Slice
	svr.DeleteL3IntfFromUpState(ipPort.IfIndex)
}

/*
 *	CheckSrcMac
 *		        a) Check for packet src mac and validate it against ifIndex mac addr
 *			    if it is same then discard the packet
 */
func (svr *NDPServer) CheckSrcMac(macAddr string) bool {
	_, exists := svr.SwitchMacMapEntries[macAddr]
	return exists
}

func (svr *NDPServer) insertNeigborInfo(nbrInfo *config.NeighborInfo) {
	svr.NeigborEntryLock.Lock()
	svr.NeighborInfo[nbrInfo.IpAddr] = *nbrInfo
	svr.neighborKey = append(svr.neighborKey, nbrInfo.IpAddr)
	svr.NeigborEntryLock.Unlock()
}

/*
 *	CheckCallUpdateNeighborInfo
 *			a) It will first check whether a neighbor exists in the neighbor cache
 *			b) If it doesn't exists then we create neighbor in the platform
 *		        a) It will update ndp server neighbor info cache with the latest information
 */
func (svr *NDPServer) CheckCallUpdateNeighborInfo(nbrInfo *config.NeighborInfo) {
	_, exists := svr.NeighborInfo[nbrInfo.IpAddr]
	if exists {
		return
	}
	debug.Logger.Info(fmt.Sprintln("Calling create ipv6 neighgor for global nbrinfo is", nbrInfo))
	// ipaddr, macAddr, vlanId, ifIndex --- Global IPv6 Address
	_, err := svr.SwitchPlugin.CreateIPv6Neighbor(nbrInfo.IpAddr, nbrInfo.MacAddr, nbrInfo.VlanId, nbrInfo.IfIndex)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("create ipv6 global neigbor failed for", nbrInfo, "error is", err))
	}
	svr.insertNeigborInfo(nbrInfo)
}

/*
 *	ProcessRxPkt
 *		        a) Check for runtime information
 *			b) Validate & Parse Pkt, which gives ipAddr, MacAddr
 *			c) PopulateVlanInfo will check if the port is untagged port or not and based of that
 *			   vlan id will be selected
 *			c) CreateIPv6 Neighbor entry
 */
func (svr *NDPServer) ProcessRxPkt(ifIndex int32, pkt gopacket.Packet) {
	_, exists := svr.L3Port[ifIndex]
	if !exists {
		return
	}
	nbrInfo := &config.NeighborInfo{}
	err := svr.Packet.ValidateAndParse(nbrInfo, pkt)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Validating and parsing Pkt Failed:", err))
		return
	}
	if nbrInfo.PktOperation == byte(packet.PACKET_DROP) {
		debug.Logger.Err(fmt.Sprintln("Dropping Neighbor Solicitation message for", nbrInfo.IpAddr))
		return
	} else if nbrInfo.State == packet.INCOMPLETE {
		debug.Logger.Err(fmt.Sprintln("Received Neighbor Solicitation message for", nbrInfo.IpAddr))
		return
	} else if nbrInfo.State == packet.REACHABLE {
		switchMac := svr.CheckSrcMac(nbrInfo.MacAddr)
		if switchMac {
			debug.Logger.Info(fmt.Sprintln(
				"Received Packet from same port and hence ignoring the packet:", nbrInfo))
			return
		}
		svr.PopulateVlanInfo(nbrInfo, ifIndex)
		svr.CheckCallUpdateNeighborInfo(nbrInfo)
	} else {
		debug.Logger.Alert(fmt.Sprintln("Handle state", nbrInfo.State, "after packet validation & parsing"))
	}
	return
}
