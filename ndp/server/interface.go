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
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"l3/ndp/config"
	"l3/ndp/debug"
	"l3/ndp/packet"
	"net"
	"time"
	"utils/commonDefs"
)

const (
	NDP_PCAP_FILTER                              = "(ip6[6] == 0x3a) and (ip6[40] >= 133 && ip6[40] <= 137)"
	NDP_PCAP_TIMEOUT                             = 1 * time.Second
	NDP_PCAP_SNAPSHOTlEN                         = 1024
	NDP_PCAP_PROMISCUOUS                         = false
	MIN_DELAY_BETWEEN_RAS                  uint8 = 3 // RFC: 4861
	MAX_INITIAL_RTR_ADVERTISEMENTS         uint8 = 3
	MAX_INITIAL_RTR_ADVERT_INTERVAL        uint8 = 16
	ALL_NODES_MULTICAST_IPV6_ADDRESS             = "ff02::1"
	ALL_NODES_MULTICAST_LINK_LAYER_ADDRESS       = "33:33:00:00:00:01"

	NDP_DEFAULT_RTR_ADVERTISEMENT_INTERVAL uint8  = 5
	NDP_DEFAULT_RETRANSMIT_INTERVAL        uint32 = 1
	NDP_DEFAULT_REACHABLE_INTERVAL         uint32 = 30000
)

type PcapBase struct {
	// Pcap Handler for Each Port
	PcapHandle *pcap.Handle
	PcapCtrl   chan bool
	// at any give time there can be two users for Pcap..
	// if 0 then only start rx/tx
	// if 1 then only stop rx/tx
	PcapUsers uint8
}

type Interface struct {
	PcapBase
	IntfRef           string
	IfIndex           int32
	IpAddr            string // CIDR Format
	LinkLocalIp       string // CIDR format
	MsgType           string
	OperState         string
	reachableTime     uint32
	retransTime       uint32
	routerLifeTime    uint16
	raRestransmitTime uint8 // @TODO: get it from user
	raTimer           *time.Timer
	initialRASend     uint8                   // on port up we have to send 3 RA before kicking in config timer
	globalScope       string                  // absolute
	linkScope         string                  // absolute
	Neighbor          map[string]NeighborInfo // key is NbrIp_NbrMac to handle move scenario's
	PktDataCh         chan config.PacketData
}

func (intf *Interface) addIP(ipAddr string) {
	if isLinkLocal(ipAddr) {
		intf.LinkLocalIp = ipAddr
		ip, _, err := net.ParseCIDR(intf.LinkLocalIp)
		if err != nil {
			debug.Logger.Err("Parsing link local ip failed", err)
		} else {
			intf.linkScope = ip.String()
		}
	} else {
		intf.IpAddr = ipAddr
		ip, _, err := net.ParseCIDR(intf.IpAddr)
		if err != nil {
			debug.Logger.Err("Parsing Global Scope ip failed", err)
		} else {
			intf.globalScope = ip.String()
		}
	}
}

func (intf *Interface) removeIP(ipAddr string) {
	if isLinkLocal(ipAddr) {
		intf.LinkLocalIp = ""
		intf.linkScope = ""
	} else {
		intf.IpAddr = ""
		intf.globalScope = ""
	}
}

/*
 * common init params between InitIntf and CreateIntf
 */
func (intf *Interface) commonInit(ipAddr string, pktCh chan config.PacketData, gCfg NdpConfig) {
	intf.addIP(ipAddr)
	// Pcap Init
	intf.PcapBase.PcapHandle = nil
	intf.PcapBase.PcapCtrl = nil
	intf.PcapBase.PcapUsers = 0
	// Timers Value Init
	intf.retransTime = gCfg.RetransTime             //1       // config value ms
	intf.reachableTime = gCfg.ReachableTime         //30000 // config value ms
	intf.raRestransmitTime = gCfg.RaRestransmitTime //5 // config value s ADAM asked for 5 seconds :)
	intf.routerLifeTime = 1800                      // config value s
	intf.initialRASend = 0
	intf.raTimer = nil
	// Neighbor Init
	intf.PktDataCh = pktCh
	intf.Neighbor = make(map[string]NeighborInfo, 10)
}

/*
 * Init Interface will be called during bootup when we do Get ALL ipv6 intfs
 */
func (intf *Interface) InitIntf(obj *commonDefs.IPv6IntfState, pktCh chan config.PacketData, gCfg NdpConfig) {
	intf.IntfRef = obj.IntfRef
	intf.IfIndex = obj.IfIndex
	intf.OperState = obj.OperState
	intf.commonInit(obj.IpAddr, pktCh, gCfg)
}

/*
 * De-Init Interface will be called during delete ip interface
 */
func (intf *Interface) DeInitIntf() []string {
	deleteEntries, _ := intf.DeleteAll()
	intf.PcapBase.PcapHandle = nil
	intf.PcapBase.PcapCtrl = nil
	intf.PcapBase.PcapUsers = 0
	intf.removeIP(intf.IpAddr)
	intf.removeIP(intf.LinkLocalIp)
	// Timers Value De-Init
	intf.raTimer = nil
	// Delete Nbrmap
	intf.Neighbor = nil
	return deleteEntries
}

/*
 * CreateIntf is called during CreateIPInterface notification
 */
func (intf *Interface) CreateIntf(obj *config.IPIntfNotification, pktCh chan config.PacketData, gCfg NdpConfig) {
	intf.IntfRef = obj.IntfRef
	intf.IfIndex = obj.IfIndex
	intf.commonInit(obj.IpAddr, pktCh, gCfg)
	debug.Logger.Info("Created IP interface", intf.IntfRef, "ifIndex:", intf.IfIndex,
		"GS:", intf.globalScope, "LS:", intf.linkScope, "Pcap Users are:", intf.PcapUsers)
}

/*
 * If Entry Already exists during CreateIPInterface then Update Interface will be called
 */
func (intf *Interface) UpdateIntf(ipAddr string) {
	intf.addIP(ipAddr)
	debug.Logger.Debug("Received update notification for ifIndex", intf.IfIndex,
		"when entry already exist in the database. Received Ip:", ipAddr, "global scope:",
		intf.IpAddr, "link scope ip:", intf.LinkLocalIp)
}

func (intf *Interface) deleteNbrList() ([]string, error) {
	if intf.PcapBase.PcapHandle == nil && intf.PcapBase.PcapUsers == 0 {
		intf.StopRATimer()
		deleteEntries, err := intf.FlushNeighbors()
		return deleteEntries, err
	}
	debug.Logger.Debug("No neighbors to be deleted for interface:", intf.IntfRef, intf.IpAddr, intf.LinkLocalIp)
	return make([]string, 0), nil
}

/*
 * DeleteIntf will kill pcap, flush neighbors and then stop all timers
 */
func (intf *Interface) DeleteIntf(ipAddr string) ([]string, error) {
	debug.Logger.Debug("Deleting Interface Called for:", intf.IntfRef, intf.IpAddr, intf.LinkLocalIp)
	//intf.removeIP(ipAddr)
	intf.DeletePcap()
	return intf.deleteNbrList()
}

/*
 * Delete All will delete ip address and then remove entire pcap
 */
func (intf *Interface) DeleteAll() ([]string, error) {
	//intf.removeIP(intf.LinkLocalIp)
	intf.DeletePcap()
	//intf.removeIP(intf.IpAddr)
	intf.DeletePcap()
	return intf.deleteNbrList()
}

/*
 * API: will create pcap handler for each port
 *		1) check if pcap users are > 0.. if so then just add pcap user and move on
 *		2) if no pcap users then check for PcapHandler and then create a new pcap handler
 *		3) Check if PcapCtrl is created or not..
 */
func (intf *Interface) CreatePcap() (err error) {
	if intf.PcapBase.PcapUsers != 0 {
		// update pcap user and move on
		intf.addPcapUser()
		debug.Logger.Info("Updating total pcap user for", intf.IntfRef, "to", intf.PcapBase.PcapUsers)
		debug.Logger.Info("Start receiving packets for GS:", intf.IpAddr, "LS:", intf.LinkLocalIp,
			"on Port", intf.IntfRef)
		return nil
	}
	if intf.PcapBase.PcapHandle == nil {
		name := intf.IntfRef
		intf.PcapBase.PcapHandle, err = pcap.OpenLive(name, NDP_PCAP_SNAPSHOTlEN, NDP_PCAP_PROMISCUOUS, NDP_PCAP_TIMEOUT)
		if err != nil {
			debug.Logger.Err("Creating Pcap Handler failed for interface:", name, "Error:", err)
			return err
		}
		err = intf.PcapBase.PcapHandle.SetBPFFilter(NDP_PCAP_FILTER)
		if err != nil {
			debug.Logger.Err("Creating BPF Filter failed Error", err)
			intf.PcapBase.PcapHandle = nil
			return err
		}
	}
	// create pcap ctrl channel if not created
	if intf.PcapBase.PcapCtrl == nil {
		intf.PcapBase.PcapCtrl = make(chan bool)
	}
	intf.addPcapUser()
	return err
}

/*
 * API: add pcap users
 */
func (intf *Interface) addPcapUser() {
	intf.PcapBase.PcapUsers += 1
}

/*
 * API: add pcap users
 */
func (intf *Interface) deletePcapUser() {
	intf.PcapBase.PcapUsers -= 1
}

/*
 * DeletePcap Handler
 *	1) fpPort1 has one ip address, bypass the check and delete pcap
 *	2) fpPort1 has two ip address
 *		a) 2003::2/64 	- Global Scope
 *		b) fe80::123/64 - Link Scope
 *		In this case we will get two Notification for port down from the chip, one is for
 *		Global Scope Ip and second is for Link Scope..
 *		On first Notification NDP will update pcap users and move on. Only when second delete
 *		notification comes then NDP will delete pcap
 */
func (intf *Interface) DeletePcap() {
	if intf.PcapBase.PcapHandle == nil {
		// create ip interface but state down will not have pcap handler created
		debug.Logger.Debug("No pcap created and hence returning")
		return
	}
	if intf.PcapBase.PcapUsers > 0 {
		debug.Logger.Info("Updating total pcap user for", intf.IntfRef, "to", intf.PcapBase.PcapUsers)
		debug.Logger.Info("Stop receiving packets for ip:", intf.IpAddr, "on Port", intf.IntfRef)
		intf.deletePcapUser()
	}
	if intf.PcapBase.PcapUsers != 0 {
		// there are still some pcap users and hence we should not delete
		return
	}

	// Inform go routine spawned for intf to exit..
	intf.PcapBase.PcapCtrl <- true
	<-intf.PcapBase.PcapCtrl

	// once go routine is exited, delete pcap handler
	if intf.PcapBase.PcapHandle != nil {
		intf.PcapBase.PcapHandle.Close()
		intf.PcapBase.PcapHandle = nil
	}

	// deleted ctrl channel to avoid any memory usage
	intf.PcapBase.PcapCtrl = nil
	intf.PcapBase.PcapUsers = 0 // set to zero
}

func (intf *Interface) writePkt(pkt []byte) error {
	if intf.PcapBase.PcapHandle != nil {
		err := intf.PcapBase.PcapHandle.WritePacketData(pkt)
		if err != nil {
			debug.Logger.Err("Sending Packet failed error:", err)
			return errors.New("Sending Packet Failed")
		}
	} else {
		debug.Logger.Warning("Pcap deleted for interface:", intf.IntfRef)
		return errors.New(fmt.Sprintln("Pcap deleted for interface:", intf.IntfRef))
	}
	return nil
}

/*
 * Receive Ndp Packet and push it on the pktCh
 */
func (intf *Interface) ReceiveNdpPkts(pktCh chan *RxPktInfo) {
	if intf.PcapBase.PcapHandle == nil {
		debug.Logger.Err("pcap handler for port:", intf.IntfRef, "is not valid. ABORT!!!!")
		return
	}
	src := gopacket.NewPacketSource(intf.PcapBase.PcapHandle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case pkt, ok := <-in:
			if !ok {
				continue
			}
			pktCh <- &RxPktInfo{pkt, intf.IfIndex}
		case <-intf.PcapBase.PcapCtrl:
			intf.PcapBase.PcapCtrl <- true
			return
		}
	}
	return
}

/*
 *  On physical link down.. server will request to delete all the neighbors from the cache..
 *  We will iterate over all the neighbors, stop its timer and delete the neighbor cache
 *  @NOTE: Always start from the bottom most layer as we never know when golang will run its garbage collector
 */
func (intf *Interface) FlushNeighbors() ([]string, error) {
	// during link local down we will have CIDR format ip
	debug.Logger.Debug("Deleting all neighbor entries for interface:", intf.IntfRef)
	deleteEntries := make([]string, 0)
	for _, nbr := range intf.Neighbor {
		nbr.DeInit()
		deleteEntries = append(deleteEntries, nbr.IpAddr)
		delete(intf.Neighbor, nbr.IpAddr)
	}
	// do not delete link information here... only if IP interface is deleted then we need to delete
	// link information
	return deleteEntries, nil
}

/*
 * flush neighbors per ip address
 */
func (intf *Interface) FlushNeighborPerIp(nbrKey, ipAddr string) ([]string, error) {
	deleteEntries := make([]string, 0)
	nbr, exists := intf.Neighbor[nbrKey]
	if !exists {
		return deleteEntries, errors.New("No Neighbor found for:" + nbrKey)
	}
	nbr.DeInit()
	deleteEntries = append(deleteEntries, ipAddr)
	delete(intf.Neighbor, nbrKey)
	return deleteEntries, nil
}

/*
 *  helper function for creating key based on nd Information
 */
func (intf *Interface) createNbrKey(ndInfo *packet.NDInfo) (nbrkey string) {
	if ndInfo.SrcIp == intf.globalScope || ndInfo.SrcIp == intf.linkScope {
		// use destination ip as index to neighbor information
		nbrkey = ndInfo.DstIp + "_" + ndInfo.DstMac
	} else {
		nbrkey = ndInfo.SrcIp + "_" + ndInfo.SrcMac
	}
	return nbrkey
}

/*
 * process nd will be called during received message
 */
func (intf *Interface) ProcessND(ndInfo *packet.NDInfo) (*config.NeighborConfig, NDP_OPERATION) {
	switch ndInfo.PktType {
	case layers.ICMPv6TypeNeighborSolicitation:
		return intf.processNS(ndInfo)
	case layers.ICMPv6TypeNeighborAdvertisement:
		return intf.processNA(ndInfo)
	case layers.ICMPv6TypeRouterAdvertisement:
		return intf.processRA(ndInfo)
	}

	return nil, IGNORE
}

/*
 * send neighbor discover messages on timer expiry
 */
func (intf *Interface) SendND(pktData config.PacketData, mac string) NDP_OPERATION {
	switch pktData.SendPktType {
	case layers.ICMPv6TypeNeighborSolicitation:
		return intf.SendNS(mac, pktData.NeighborMac, pktData.NeighborIp)
	case layers.ICMPv6TypeNeighborAdvertisement:
		// @TODO: implement this
	case layers.ICMPv6TypeRouterAdvertisement:
		intf.SendRA(mac)
	}
	return IGNORE
}
