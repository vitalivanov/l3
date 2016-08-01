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
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket/layers"
	"l3/ndp/config"
	"l3/ndp/debug"
	"net"
)

/*
 * If the IP Destination Address is a multicast address the
 *       Solicited flag is zero.
 * All included options have a length that is greater than zero.
 */
func (nd *NDInfo) ValidateNDAInfo(icmpFlags []byte, dstIP net.IP) error {
	if dstIP.IsMulticast() {
		flags := binary.BigEndian.Uint16(icmpFlags[0:2])
		if (flags & 0x4000) == 0x4000 {
			return errors.New(fmt.Sprintln("Check for If Destination Address is a multicast",
				"address then the Solicited flag is zero, Failed"))
		}
	}
	// @TODO: need to add support for options length
	return nil
}

/*
 * When we get advertisement packet we need to update the mac address of peer and move the state to
 * REACHABLE
 *
 * If srcIP is my own IP then linux is responding for earlier solicitation message and hence we need to update
 * our cache entry with reachable
 * If srcIP is peer ip then we need to use dst ip to get link information and then update cache entry to be
 * reachable and also update peer mac address into the cache
 * @TODO: handle un-solicited Neighbor Advertisemtn
 */
func (p *Packet) HandleNAMsg(hdr *layers.ICMPv6, srcIP, dstIP net.IP) (*NDInfo, error) {
	ndInfo := &NDInfo{}
	ndInfo.DecodeNDInfo(hdr.LayerPayload())
	if ndInfo.IsTargetMulticast() {
		return nil, errors.New(fmt.Sprintln("Targent Address specified", ndInfo.TargetAddress,
			"is a multicast address"))
	}
	err := ndInfo.ValidateNDAInfo(hdr.TypeBytes, dstIP)
	if err != nil {
		return nil, err
	}

	// if my own ip is srcIP
	debug.Logger.Debug("NA: Searching for my link informating using SrcIP:", srcIP.String())
	myLink, exists := p.GetLink(srcIP.String())
	if exists {
		cache, found := myLink.NbrCache[dstIP.String()]
		if !found {
			debug.Logger.Err("No Neigbor Entry found for:", dstIP.String(), "link IP:", srcIP.String())
			return nil, errors.New("No Neigbor Entry found for:" + dstIP.String() +
				" link IP:" + srcIP.String())
		}
		cache.State = REACHABLE
		cache.RchTimer()
		debug.Logger.Debug("MYOWNNA: nbrCach (key, value) ---> (", dstIP.String(), ",", cache, ")")
		myLink.NbrCache[dstIP.String()] = cache
		p.SetLink(srcIP.String(), myLink)
	} else {
		debug.Logger.Debug("NA: Searching for link information using dstIP:", dstIP.String())
		link, found := p.GetLink(dstIP.String())
		if !found {
			return nil, errors.New("No link found for:" + dstIP.String())
		}
		cache, exists := link.NbrCache[srcIP.String()]
		if !exists {
			debug.Logger.Err("No Neigbor Entry found for:", srcIP.String(), "link IP:", dstIP.String())
			return nil, errors.New("No Neigbor Entry found for:" + srcIP.String() +
				" link IP:" + dstIP.String())
		}
		cache.State = REACHABLE
		cache.RchTimer()
		if len(ndInfo.Options) > 0 {
			for _, option := range ndInfo.Options {
				if option.Type == NDOptionTypeTargetLinkLayerAddress {
					mac := net.HardwareAddr(option.Value)
					cache.LinkLayerAddress = mac.String()
				}
			}
		}
		debug.Logger.Debug("PEERNA: nbrCach (key, value) ---> (", srcIP.String(), ",", cache, ")")
		link.NbrCache[srcIP.String()] = cache
		p.SetLink(dstIP.String(), link)
	}
	return ndInfo, nil
}

func (p *Packet) GetNbrInfoUsingNAPkt(eth *layers.Ethernet, v6hdr *layers.IPv6, ndInfo *NDInfo) config.NeighborInfo {
	nbrInfo := config.NeighborInfo{}
	// Update nbrInfo with state & pkt operation type
	// During Neighbor Advertisement we will use dstIP to get link information
	link, found := p.GetLink(v6hdr.DstIP.String())
	if found {
		if entry, exists := link.NbrCache[v6hdr.SrcIP.String()]; exists {
			nbrInfo.State = entry.State
			if entry.LinkLayerAddress != "" {
				nbrInfo.MacAddr = entry.LinkLayerAddress
			} else {
				nbrInfo.MacAddr = eth.SrcMAC.String()
			}
			nbrInfo.IpAddr = entry.IpAddr
			nbrInfo.IfIndex = link.PortIfIndex
		} else {
			nbrInfo.PktOperation = byte(PACKET_DROP)
			debug.Logger.Debug("dropping incoming neighbor advertisement as no nbr found")
		}
	} else {
		nbrInfo.PktOperation = byte(PACKET_DROP)
		debug.Logger.Debug("dropping incoming neighbor advertisement as no link found")
	}
	return nbrInfo
}
