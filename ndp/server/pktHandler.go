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
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"l3/ndp/config"
	"l3/ndp/debug"
)

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
		debug.Logger.Err("Failed starting RX/TX for interface which was not created, ifIndex:",
			ifIndex, "is not allowed")
		return
	}

	// create pcap handler if there is none created right now
	err := ipPort.CreatePcap()
	if err != nil {
		debug.Logger.Err("Failed Creating Pcap Handler, err:", err, "for interface:", ipPort.IntfRef)
		return
	}
	debug.Logger.Info("Start rx/tx for port:", ipPort.IntfRef, "ifIndex:",
		ipPort.IfIndex, "ip GS:", ipPort.IpAddr, "LS:", ipPort.LinkLocalIp, "is done")

	// Spawn go routines for rx & tx
	go ipPort.ReceiveNdpPkts(svr.RxPktCh)
	svr.ndpUpL3IntfStateSlice = append(svr.ndpUpL3IntfStateSlice, ifIndex)

	// On Port Up Send RA packets
	pktData := config.PacketData{
		SendPktType: layers.ICMPv6TypeRouterAdvertisement,
	}
	ipPort.SendND(pktData, svr.SwitchMac)
	svr.L3Port[ifIndex] = ipPort
}

/*
 *	StopRxTx       a) Check if entry is present in the map
 *		       b) If present then send a ctrl signal to stop receiving packets
 *		       c) block until cleanup is going on
 *		       c) delete the entry from up interface slice
 */
func (svr *NDPServer) StopRxTx(ifIndex int32, ipAddr string) {
	ipPort, exists := svr.L3Port[ifIndex]
	if !exists {
		debug.Logger.Err("No entry found for ifIndex:", ifIndex)
		return
	}

	// delete interface will delete pcap if needed and return the deleteEntries
	/* The below check is based on following assumptions:
	 *	1) fpPort1 has one ip address, bypass the check and delete pcap
	 *	2) fpPort1 has two ip address
	 *		a) 2003::2/64 	- Global Scope
	 *		b) fe80::123/64 - Link Scope
	 *		In this case we will get two Notification for port down from the chip, one is for
	 *		Global Scope Ip and second is for Link Scope..
	 *		On first Notification NDP will update pcap users and move on. Only when second delete
	 *		notification comes then NDP will delete pcap
	 */
	var deleteEntries []string
	var err error
	if ipAddr == "ALL" {
		debug.Logger.Debug("Deleting all entries")
		deleteEntries, err = ipPort.DeleteAll()
	} else {
		debug.Logger.Debug("Deleing interface:", ipAddr)
		deleteEntries, err = ipPort.DeleteIntf(ipAddr)
	}
	if len(deleteEntries) > 0 && err == nil {
		debug.Logger.Info("Server Got Neigbor Delete for interface:", ipPort.IntfRef)
		svr.DeleteNeighborInfo(deleteEntries, ifIndex)
	}

	svr.L3Port[ifIndex] = ipPort
	if len(deleteEntries) == 0 {
		return // only one ip address got deleted
	}
	debug.Logger.Info("Stop rx/tx for port:", ipPort.IntfRef, "ifIndex:",
		ipPort.IfIndex, "ip GS:", ipPort.IpAddr, "LS:", ipPort.LinkLocalIp, "is done")
	// Delete Entry from Slice only after all the ip's are deleted
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

/*
 *	insertNeighborInfo: Helper API to update list of neighbor keys that are created by ndp
 */
func (svr *NDPServer) insertNeigborInfo(nbrInfo *config.NeighborConfig) {
	svr.NeigborEntryLock.Lock()
	svr.NeighborInfo[nbrInfo.IpAddr] = *nbrInfo
	svr.neighborKey = append(svr.neighborKey, nbrInfo.IpAddr)
	svr.NeigborEntryLock.Unlock()
}

/*
 *	deleteNeighborInfo: Helper API to update list of neighbor keys that are deleted by ndp
 *	@NOTE: caller is responsible for acquiring the lock to access slice
 */
func (svr *NDPServer) deleteNeighborInfo(nbrIp string) {
	for idx, _ := range svr.neighborKey {
		if svr.neighborKey[idx] == nbrIp {
			svr.neighborKey = append(svr.neighborKey[:idx],
				svr.neighborKey[idx+1:]...)
			break
		}
	}
}

/*
 *	 CreateNeighborInfo
 *			a) It will first check whether a neighbor exists in the neighbor cache
 *			b) If it doesn't exists then we create neighbor in the platform
 *		        a) It will update ndp server neighbor info cache with the latest information
 */
func (svr *NDPServer) CreateNeighborInfo(nbrInfo *config.NeighborConfig) {
	debug.Logger.Debug("Calling create ipv6 neighgor for global nbrinfo is", nbrInfo.IpAddr, nbrInfo.MacAddr,
		nbrInfo.VlanId, nbrInfo.IfIndex)
	_, err := svr.SwitchPlugin.CreateIPv6Neighbor(nbrInfo.IpAddr, nbrInfo.MacAddr,
		nbrInfo.VlanId, nbrInfo.IfIndex)
	if err != nil {
		debug.Logger.Err("create ipv6 global neigbor failed for", nbrInfo, "error is", err)
		// do not enter that neighbor in our neigbor map
		return
	}
	svr.SendIPv6CreateNotification(nbrInfo.IpAddr, nbrInfo.IfIndex)
	svr.insertNeigborInfo(nbrInfo)
}

func (svr *NDPServer) deleteNeighbor(nbrIp string, ifIndex int32) {
	// Inform clients that neighbor is gonna be deleted
	svr.SendIPv6DeleteNotification(nbrIp, ifIndex)
	// Request asicd to delete the neighbor
	_, err := svr.SwitchPlugin.DeleteIPv6Neighbor(nbrIp)
	if err != nil {
		debug.Logger.Err("delete ipv6 neigbor failed for", nbrIp, "error is", err)
	}
	// delete the entry from neighbor map
	delete(svr.NeighborInfo, nbrIp)
	svr.deleteNeighborInfo(nbrIp)
}

/*
 *	 DeleteNeighborInfo
 *			a) It will first check whether a neighbor exists in the neighbor cache
 *			b) If it doesn't exists then we will move on to next neighbor
 *		        c) If exists then we will call DeleteIPV6Neighbor for that entry and remove
 *			   the entry from our runtime information
 */
func (svr *NDPServer) DeleteNeighborInfo(deleteEntries []string, ifIndex int32) {
	svr.NeigborEntryLock.Lock()
	for _, nbrIp := range deleteEntries {
		debug.Logger.Debug("Calling delete ipv6 neighbor for nbrIp:", nbrIp)
		svr.deleteNeighbor(nbrIp, ifIndex)
	}
	svr.NeigborEntryLock.Unlock()
}

/*
 *	ProcessRxPkt
 *		        a) Check for runtime information
 *			b) Validate & Parse Pkt, which gives ipAddr, MacAddr
 *			c) PopulateVlanInfo will check if the port is untagged port or not and based of that
 *			   vlan id will be selected
 *			c) CreateIPv6 Neighbor entry
 */
func (svr *NDPServer) ProcessRxPkt(ifIndex int32, pkt gopacket.Packet) error {
	ipPort, exists := svr.L3Port[ifIndex]
	if !exists {
		return errors.New(fmt.Sprintln("Entry for ifIndex:", ifIndex, "doesn't exists"))
	}
	ndInfo, err := svr.Packet.DecodeND(pkt)
	if err != nil || ndInfo == nil {
		return errors.New(fmt.Sprintln("Failed decoding ND packet, error:", err))
	}
	nbrInfo, operation := ipPort.ProcessND(ndInfo)
	if nbrInfo == nil || operation == IGNORE {
		//debug.Logger.Warning("nbrInfo:", nbrInfo, "operation:", operation)
		return nil
	}
	switch operation {
	case CREATE:
		svr.PopulateVlanInfo(nbrInfo, ifIndex)
		svr.CreateNeighborInfo(nbrInfo)
	case DELETE:
		svr.deleteNeighbor(nbrInfo.IpAddr, ifIndex) // used mostly by RA
	}
	return nil
}

func (svr *NDPServer) ProcessTimerExpiry(pktData config.PacketData) error {
	l3Port, exists := svr.L3Port[pktData.IfIndex]
	if !exists {
		return errors.New(fmt.Sprintln("Entry for ifIndex:", pktData.IfIndex,
			"doesn't exists and hence cannot process timer expiry event for neighbor:", pktData))
	}
	// fix this when we have per port mac addresses
	operation := l3Port.SendND(pktData, svr.SwitchMac)
	if operation == DELETE {
		svr.deleteNeighbor(pktData.NeighborIp, pktData.IfIndex)
	}
	svr.L3Port[pktData.IfIndex] = l3Port
	return nil
}
