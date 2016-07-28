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
	_ "fmt"
	"github.com/google/gopacket/pcap"
	_ "l3/ndp/debug"
	_ "net"
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
	/*
		ip, _, err := net.ParseCIDR(ipAddr)
		if err != nil {
			return errors.New(fmt.Sprintln("Parsing CIDR", ipAddr, "failed with Error:", err))
		}
			cache, exists := p.NbrCache[ip.String()]
			if !exists {
				debug.Logger.Info(fmt.Sprintln("cache entry for ipAddr", ip, "not found in nbr cache.",
					"Waiting for linux to finish of neighbor duplicate detection"))
				return nil
			}
			pktToSend := ConstructNSPacket(ip.String(), "::", cache.LinkLayerAddress, IPV6_ICMPV6_MULTICAST_DST_MAC, ip.To16())
			return p.SendNDPkt(pktToSend, pHdl)
	*/
	return nil
}

/*
 *    Helper function to send raw bytes on a given pcap handler
 */
func (p *Packet) SendNDPkt(pkt []byte, pHdl *pcap.Handle) error {
	if pHdl == nil {
		return errors.New("Invalid Pcap Handler")
	}
	err := pHdl.WritePacketData(pkt)
	if err != nil {
		return errors.New("Sending Packet Failed")
	}
	return nil
}
