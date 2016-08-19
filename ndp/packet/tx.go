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
	"time"
)

/*
 *    Port is coming up for the first time and linux is sending Neighbor Solicitation message targeted at the
 *    neighbor. In this case we will wait for linux to finish off the neighbor detection and hence ignore
 *    sending the NS packet...
 *    However, if the ipAddr is already cached in the neighbor cache then it means that it has already been
 *    solicitated before......In this case we will send out multicast solicitation and whoever repsonds will we
 *    learn about them via Neighbor Advertisement... That way our nexthop neighbor entry is always up-to-date
 */
func (p *Packet) SendNAMsg(srcMac, ipAddr string, pHdl *pcap.Handle) error {
	ip, _, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return errors.New(fmt.Sprintln("Parsing CIDR", ipAddr, "failed with Error:", err))
	}
	// Hard Coded this value... @jgheewala: fix this asap
	pktToSend := ConstructRAPacket(srcMac, "33:33:00:00:00:01", ip.String(), "ff02::1")
	/*
			link, exists := p.GetLink(ip.String())
			if !exists {
				debug.Logger.Debug("link entry for ipAddr", ip, "not found in linkInfo.",
					"Waiting for linux to finish of neighbor duplicate detection")
				return nil
			}
			debug.Logger.Debug("link info", link, "ip address", ip)
		pktToSend := ConstructNSPacket(link.LinkLocalAddress, IPV6_ICMPV6_MULTICAST_DST_MAC, ip.String(),
			SOLICITATED_NODE_ADDRESS)
		debug.Logger.Debug("sending pkt from link", link.LinkLocalAddress, "bytes are:", pktToSend)
	*/
	//@HACK: jgheewala fix this with re-ordering of links

	var raTimer *time.Timer
	resends := 0
	p.SendNDPkt(pktToSend, pHdl)
	var resendRAMsg_func func()
	resendRAMsg_func = func() {
		debug.Logger.Debug("Re-sending RA for", srcMac, ipAddr)
		err := p.SendNDPkt(pktToSend, pHdl)
		if err != nil {
			debug.Logger.Err("Failed sending pkt for", srcMac, ipAddr, "re-send number", resends)
		}
		if resends <= 3 {
			raTimer.Reset(time.Duration(16) * time.Second)
			resends++
		}
	}
	raTimer = time.AfterFunc(time.Duration(16)*time.Second, resendRAMsg_func)
	return nil //p.SendNDPkt(pktToSend, pHdl)
}

/*
 *    Helper function to send raw bytes on a given pcap handler
 */
func (p *Packet) SendNDPkt(pkt []byte, pHdl *pcap.Handle) error {
	if pHdl == nil {
		debug.Logger.Err("Invalid Pcap Handler")
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
 *    Check how many solicitations are send out to the neighbor,
 *    if != MAX_UNICAST_SOLICIT then send Unicast NS
 */
func (p *Packet) RetryUnicastSolicitation(srcIP, dstIP string, pHdl *pcap.Handle) bool {
	link, exists := p.GetLink(srcIP)
	if !exists {
		debug.Logger.Info("Link is not valid, delete neigbor")
		return false
	}
	cache, exists := link.NbrCache[dstIP]
	if !exists {
		debug.Logger.Err("No Neighbor entry", dstIP, "found for", srcIP)
		return false
	}
	if cache.ProbesSent == MAX_UNICAST_SOLICIT {
		return false
	}

	// use pktData.IpAddr because that will be your src ip without CIDR format, same goes for NeighborIP
	p.SendUnicastNeighborSolicitation(srcIP, dstIP, pHdl)
	return true
}

/*
 *    Send Unicast Neighbor Solicitation on Timer Expiry
 */
func (p *Packet) SendUnicastNeighborSolicitation(srcIP, dstIP string, pHdl *pcap.Handle) error {
	link, exists := p.GetLink(srcIP)
	if !exists {
		debug.Logger.Err("Sending Unicast NS Failed as2 link entry for ipAddr", srcIP,
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
	debug.Logger.Debug("link info", link, "src ip address", srcIP, "dst ip", dstIP)
	pktToSend := ConstructNSPacket(link.LinkLocalAddress, cache.LinkLayerAddress, srcIP, dstIP)
	debug.Logger.Debug("sending pkt from link", link.LinkLocalAddress, "bytes are:", pktToSend)
	err := p.SendNDPkt(pktToSend, pHdl)
	if err != nil {
		debug.Logger.Err("packet send failed:", err)
		return errors.New(fmt.Sprintln("packet send failed:", err))
	}

	// when sending unicast packet re-start retransmit/delay probe timer.. rest all will be taken care of when
	// NA packet is received..
	if cache.State == REACHABLE {
		// This means that Reachable Timer has expierd and hence we are sending Unicast Message..
		// Lets set the time for delay first probe
		cache.DelayProbe()
		cache.State = DELAY
		cache.ProbesSent = 0
	} else {
		// Probes Sent can still be zero but the state has changed to Delay..
		// Start Timer for Probe and move the state from delay to Probe
		cache.Timer()
		cache.State = PROBE
		cache.ProbesSent += 1
	}
	//cache.State = STALE
	link.NbrCache[dstIP] = cache
	p.SetLink(srcIP, link)
	return nil
}
