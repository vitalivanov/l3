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
package packet

import (
	"errors"
	"fmt"
	"github.com/google/gopacket/pcap"
	"l3/ndp/debug"
	"net"
)

/*
 *    Port is coming up for the first time and linux is sending Neighbor Solicitation message targeted at the
 *    neighbor. In this case we will wait for linux to finish off the neighbor detection and hence ignore
 *    sending the NS packet...
 *    However, if the ipAddr is already cached in the neighbor cache then it means that it has already been
 *    solicitated before......In this case we will send out multicast solicitation and whoever repsonds will we
 *    learn about them via Neighbor Advertisement... That way our nexthop neighbor entry is always up-to-date
 */
func (p *Packet) SendNSMsgIfRequired(ipAddr string, pHdl *pcap.Handle) error {
	ip, _, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return errors.New(fmt.Sprintln("Parsing CIDR", ipAddr, "failed with Error:", err))
	}
	link, exists := p.GetLink(ip.String())
	if !exists {
		debug.Logger.Info("link entry for ipAddr", ip, "not found in linkInfo.",
			"Waiting for linux to finish of neighbor duplicate detection")
		return nil
	}
	debug.Logger.Info("link info", link, "ip address", ip)
	pktToSend := ConstructNSPacket(link.LinkLocalAddress, IPV6_ICMPV6_MULTICAST_DST_MAC, ip.String(),
		SOLICITATED_NODE_ADDRESS)
	debug.Logger.Info("sending pkt from link", link.LinkLocalAddress, "bytes are:", pktToSend)
	return p.SendNDPkt(pktToSend, pHdl)
}

/*
 *    Helper function to send raw bytes on a given pcap handler
 */
func (p *Packet) SendNDPkt(pkt []byte, pHdl *pcap.Handle) error {
	if pHdl == nil {
		debug.Logger.Info("Invalid Pcap Handler")
		return errors.New("Invalid Pcap Handler")
	}
	err := pHdl.WritePacketData(pkt)
	if err != nil {
		debug.Logger.Err("Sending Packet failed error:", err)
		return errors.New("Sending Packet Failed")
	}
	return nil
}

/*
 *    Send Unicast Neighbor Solicitation on Timer Expiry
 */
func (p *Packet) SendUnicastNeighborSolicitation(srcIP, dstIP string, pHdl *pcap.Handle) error {
	link, exists := p.GetLink(srcIP)
	if !exists {
		debug.Logger.Err("Sending Unicast NS Failed as link entry for ipAddr", srcIP,
			"not found in linkInfo.")
		return errors.New(fmt.Sprintln("Sending Unicast NS Failed as link entry for ipAddr", srcIP,
			"not found in linkInfo."))
	}
	cache, exists := link.NbrCache[dstIP]
	if !exists {
		debug.Logger.Err("No Neighbor Entry", dstIP, "found for", srcIP)
		// @TODO: need to send out multicast neighbor solicitation in this case....
		return errors.New(fmt.Sprintln("No Neighbor Entry", dstIP, "found for", srcIP))
	}
	debug.Logger.Info("link info", link, "src ip address", srcIP, "dst ip", dstIP)
	pktToSend := ConstructNSPacket(link.LinkLocalAddress, cache.LinkLayerAddress, srcIP, dstIP)
	debug.Logger.Info("sending pkt from link", link.LinkLocalAddress, "bytes are:", pktToSend)
	err := p.SendNDPkt(pktToSend, pHdl)
	if err != nil {
		debug.Logger.Info("packet send failed:", err)
		return errors.New(fmt.Sprintln("packet send failed:", err))
	}
	cache.Timer(link.PortIfIndex, srcIP, dstIP, link.RetransTimer, p.PktCh)
	link.NbrCache[dstIP] = cache
	p.SetLink(srcIP, link)
	return nil
}
