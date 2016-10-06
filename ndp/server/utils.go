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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"l3/ndp/config"
	"l3/ndp/debug"
	"net"
	"utils/commonDefs"
)

func isLinkLocal(ipAddr string) bool {
	ip, _, err := net.ParseCIDR(ipAddr)
	if err != nil {
		ip = net.ParseIP(ipAddr)
	}
	return ip.IsLinkLocalUnicast() && (ip.To4() == nil)
}

func (svr *NDPServer) IsIPv6Addr(ipAddr string) bool {
	ip, _, _ := net.ParseCIDR(ipAddr)
	if ip.To4() == nil {
		return true
	}

	return false
}

/*
 * helper function to create notification msg
 */
func createNotificationMsg(ipAddr string, ifIndex int32) ([]byte, error) {
	msg := commonDefs.Ipv6NeighborNotification{
		IpAddr:  ipAddr,
		IfIndex: ifIndex,
	}
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		debug.Logger.Err("Failed to marshal IPv6 Neighbor Notification message", msg, "error:", err)
		return msgBuf, err
	}

	return msgBuf, nil
}

/*
 * helper function to marshal notification and push it on to the channel
 */
func (svr *NDPServer) pushNotification(notification commonDefs.NdpNotification) {
	notifyBuf, err := json.Marshal(notification)
	if err != nil {
		debug.Logger.Err("Failed to marshal ipv6 notification before pushing it on channel error:", err)
		return
	}
	svr.notifyChan <- notifyBuf
}

/*
 *  Change L2 port state from switch asicd notification
 */
func (svr *NDPServer) updateL2Operstate(ifIndex int32, state string) {
	//l2Port, exists := svr.PhyPort[ifIndex]
	l2Port, exists := svr.L2Port[ifIndex]
	if !exists {
		debug.Logger.Err("No L2 Port found for ifIndex:", ifIndex, "hence nothing to update on OperState")
		return
	}
	l2Port.Info.OperState = state
	svr.L2Port[ifIndex] = l2Port
}

/*
 * internal api for creating pcap handler for l2 physical port for RX
 */
func (l2Port *PhyPort) createPcap(pktCh chan *RxPktInfo) (err error) {
	if l2Port.RX == nil && l2Port.Info.OperState == config.STATE_UP {
		name := l2Port.Info.Name
		l2Port.RX, err = pcap.OpenLive(name, NDP_PCAP_SNAPSHOTlEN, NDP_PCAP_PROMISCUOUS, NDP_PCAP_TIMEOUT)
		if err != nil {
			debug.Logger.Err("Creating Pcap Handler failed for l2 interface:", name, "Error:", err)
			return err
		}
		err = l2Port.RX.SetBPFFilter(NDP_PCAP_FILTER)
		if err != nil {
			debug.Logger.Err("Creating BPF Filter failed Error", err)
			l2Port.RX = nil
			return err
		}
		debug.Logger.Info("Created l2 Pcap handler for port:", l2Port.Info.Name, "now start receiving NdpPkts")
		go l2Port.L2ReceiveNdpPkts(pktCh)
	}
	return nil
}

/*
 * internal api for creating pcap handler for l2 physical port for RX
 */
func (l2Port *PhyPort) deletePcap() {
	if l2Port.RX != nil {
		l2Port.RX.Close()
		l2Port.RX = nil
	}
}

/*
 * Receive Ndp Packet and push it on the pktCh
 */
func (intf *PhyPort) L2ReceiveNdpPkts(pktCh chan *RxPktInfo) error {
	if intf.RX == nil {
		debug.Logger.Err("pcap handler for port:", intf.Info.Name, "is not valid. ABORT!!!!")
		return errors.New(fmt.Sprintln("pcap handler for port:", intf.Info.Name, "is not valid. ABORT!!!!"))
	}
	src := gopacket.NewPacketSource(intf.RX, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case pkt, ok := <-in:
			if ok {
				pktCh <- &RxPktInfo{pkt, intf.Info.IfIndex}
			} else {
				debug.Logger.Debug("Pcap closed as in is invalid exiting go routine for port:", intf.Info.Name)
				return nil
			}
		}
	}
	return nil
}

/*
 *  Creating Pcap handlers for l2 port which are marked as tag/untag for l3 vlan port and are in UP state
 */
func (svr *NDPServer) CreatePcap(ifIndex int32) error {
	debug.Logger.Info("Creating Physical Port Pcap RX Handlers for L3 Vlan, ifIndex:", ifIndex)
	vlan, exists := svr.VlanInfo[ifIndex]
	if !exists {
		debug.Logger.Err("No matching vlan found for ifIndex:", ifIndex)
		return errors.New(fmt.Sprintln("No matching vlan found for ifIndex:", ifIndex))
	}
	// open rx pcap handler for tagged ports
	for pIfIndex, _ := range vlan.TagPortsMap {
		l2Port, exists := svr.L2Port[pIfIndex]
		if exists {
			err := l2Port.createPcap(svr.RxPktCh)
			if err == nil {
				svr.L2Port[pIfIndex] = l2Port
				// reverse map updated
				svr.PhyPortToL3PortMap[pIfIndex] = ifIndex
			}
		}
	}
	// open rx pcap handler for untagged ports
	for pIfIndex, _ := range vlan.UntagPortsMap {
		l2Port, exists := svr.L2Port[pIfIndex]
		if exists {
			err := l2Port.createPcap(svr.RxPktCh)
			if err == nil {
				svr.L2Port[pIfIndex] = l2Port
				// reverse map updated
				svr.PhyPortToL3PortMap[pIfIndex] = ifIndex
			}
		}
	}
	return nil
}

/*
 *  Deleting Pcap handlers for l2 port which are marked as tag/untag for l3 vlan port and are in UP state
 */
func (svr *NDPServer) DeletePcap(ifIndex int32) {
	debug.Logger.Info("Deleting Physical Port Pcap RX Handlers for L3 Vlan, ifIndex:", ifIndex)
	vlan, exists := svr.VlanInfo[ifIndex]
	if !exists {
		debug.Logger.Err("No matching vlan found for ifIndex:", ifIndex)
		return //errors.New(fmt.Sprintln("No matching vlan found for ifIndex:", ifIndex))
	}
	// open rx pcap handler for tagged ports
	for pIfIndex, _ := range vlan.TagPortsMap {
		l2Port, exists := svr.L2Port[pIfIndex]
		if exists {
			l2Port.deletePcap()
			delete(svr.PhyPortToL3PortMap, pIfIndex)
		}
	}
	// open rx pcap handler for untagged ports
	for pIfIndex, _ := range vlan.UntagPortsMap {
		l2Port, exists := svr.L2Port[pIfIndex]
		if exists {
			l2Port.deletePcap()
			delete(svr.PhyPortToL3PortMap, pIfIndex)
		}
	}
}
