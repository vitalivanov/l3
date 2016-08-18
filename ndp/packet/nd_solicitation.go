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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"l3/ndp/config"
	"l3/ndp/debug"
	"net"
	"strings"
)

/*
 *  Range for Solicited Node Multicast Address from RFC 4291 FF02:0:0:0:0:1:FF00:0000 to FF02:0:0:0:0:1:FFFF:FFFF
 *  if srcIp == "::", i.e Unspecified address then dstIP should be solicited-node address FF02:0:0:0:0:1:FFXX:XXXX
 *  if srcIP == "::", then there should not be any source link-layer option in message
 */
func (nd *NDInfo) ValidateNDSInfo(srcIP net.IP, dstIP net.IP) error {
	if srcIP.IsUnspecified() {
		if !(dstIP[0] == IPV6_MULTICAST_BYTE && dstIP[1]&0x0f == 0x02 &&
			dstIP[11]&0x0f == 0x01 && dstIP[12] == IPV6_MULTICAST_BYTE) {
			return errors.New(fmt.Sprintln("Destination IP address",
				dstIP.String(), "is not Solicited-Node Multicast Address"))
		}
		options := nd.Options
		if len(options) > 0 {
			for _, option := range options {
				if option.Type == NDOptionTypeSourceLinkLayerAddress {
					return errors.New(fmt.Sprintln("During ND Solicitation with Unspecified",
						"address Source Link Layer Option should not be set"))
				}
			}
		}
	}
	return nil
}

/*
 *  Generic API to create Neighbor Solicitation Packet based on inputs..
 */
//func ConstructNSPacket(targetAddr, srcIP, srcMac, dstMac string, ip net.IP) []byte {
func ConstructNSPacket(srcMac, dstMac, srcIP, dstIP string) []byte {

	// Ethernet Layer Information
	srcMAC, _ := net.ParseMAC(srcMac)
	dstMAC, _ := net.ParseMAC(dstMac)

	/* Check dstMac.. if It is solicitated multicast mac address then we need to replace the lower
	 * 24 bits or 3bytes with srcMac bits or bytes
	 * for e.g: if SrcMac is aa:bb:cc:dd:ee:ff & DstMac is 33:33:ff:00:00:00
	 *	    dstMac needst to be updated with 33:33:ff:dd:ee:ff
	 */
	if strings.Compare(dstMac, IPV6_ICMPV6_MULTICAST_DST_MAC) == 0 {
		for idx := (len(srcMAC) - 4); idx < len(srcMAC); idx++ {
			dstMAC[idx] = srcMAC[idx]
		}
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	debug.Logger.Debug("ethernet layer is", *eth)

	// IPv6 Layer Information
	sip := net.ParseIP(srcIP)
	dip := net.ParseIP(dstIP)
	if strings.Compare(dstIP, SOLICITATED_NODE_ADDRESS) == 0 {
		/*
		 * Solicitated Multicast Address as dst ip.
		 * Solicitated Muticast Address is formed by:
		 *	    Taking lower 24 bits or 3 bytes of an address (unicast or anycast) and appending those
		 *	    bits or bytes to the prefix of Solicitated-Node Address FF02:0:0:0:0:1:FFXX:XXXX
		 */
		ip := sip.To16()
		for idx := (len(ip) - 3); idx < len(ip); idx++ {
			dip[idx] = ip[idx]
		}
		// updating src ip with "::"
		copy(sip, net.ParseIP(SOLICITATED_SRC_IP))
	}

	ipv6 := &layers.IPv6{
		Version:      IPV6_VERSION,
		TrafficClass: 0,
		NextHeader:   layers.IPProtocolICMPv6,
		SrcIP:        sip,
		DstIP:        dip,
		HopLimit:     HOP_LIMIT,
	}
	debug.Logger.Debug("ipv6 layer is", *ipv6)
	// ICMPV6 Layer Information
	payload := make([]byte, ICMPV6_MIN_LENGTH)
	payload[0] = byte(layers.ICMPv6TypeNeighborSolicitation)
	payload[1] = byte(0)
	binary.BigEndian.PutUint16(payload[2:4], 0) // Putting zero for checksum before calculating checksum
	binary.BigEndian.PutUint32(payload[4:], 0)  // RESERVED FLAG...
	copy(payload[8:], dip.To16())

	// Append Source Link Layer Option here
	srcOption := NDOption{
		Type:   NDOptionTypeSourceLinkLayerAddress,
		Length: 1,
		Value:  srcMAC,
	}
	payload = append(payload, byte(srcOption.Type))
	payload = append(payload, srcOption.Length)
	payload = append(payload, srcOption.Value...)
	binary.BigEndian.PutUint16(payload[2:4], getCheckSum(ipv6, payload))
	debug.Logger.Debug("icmpv6 info is", payload)
	ipv6.Length = uint16(len(payload))
	debug.Logger.Debug("ipv6 layer is", *ipv6)
	// GoPacket serialized buffer that will be used to send out raw bytes
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buffer, options, eth, ipv6, gopacket.Payload(payload))
	return buffer.Bytes()
}

/*
 *  helper function to handle incoming Neighbor solicitation messages...
 *  Case 1) SrcIP == "::"
 *		This is a message which is locally generated. In this case Target Address will be our own
 *		IP Address, which is not a Neighbor and hence we should not create a entry in NbrCache
 *  Case 2) SrcIP != "::"
 *		This is a message coming from our Neighbor. Ok now what do we need to do?
 *		If no cache entry:
 *		    Then create a cache entry and mark that entry as incomplete
 *		If cache entry exists:
 *		    Then update the state to STALE
 */
func (p *Packet) HandleNSMsg(hdr *layers.ICMPv6, srcIP, dstIP net.IP) (*NDInfo, error) {
	ndInfo := &NDInfo{}
	ndInfo.DecodeNDInfo(hdr.LayerPayload())
	if ndInfo.IsTargetMulticast() {
		return nil, errors.New(fmt.Sprintln("Targent Address specified", ndInfo.TargetAddress,
			"is a multicast address"))
	}
	err := ndInfo.ValidateNDSInfo(srcIP, dstIP)
	if err != nil {
		return nil, err
	}
	// if source ip is not "::" then only we should update the nbrCache...
	// In this case Target Address is our own IP Address
	if !srcIP.IsUnspecified() {
		// Checking is the src ip address is my own IP address, if so then get mylink directly
		debug.Logger.Debug("NS: Searching for my link informating using SrcIP:", srcIP.String())
		myLink, exists := p.LinkInfo[srcIP.String()]
		if exists {
			// my own IP address is sending NS packet...for now update the state to STALE for
			//neighbor cache
			cache, found := myLink.NbrCache[ndInfo.TargetAddress.String()]
			if !found {
				cache.InitCache(myLink.ReachableTime, myLink.RetransTimer, ndInfo.TargetAddress.String(),
					srcIP.String(), myLink.PortIfIndex, p.PktCh)
			} else {
				cache.State = STALE
			}
			myLink.NbrCache[ndInfo.TargetAddress.String()] = cache
			p.SetLink(srcIP.String(), myLink)
			debug.Logger.Debug("MYNS: nbrCach (key, value) ---> (", ndInfo.TargetAddress.String(),
				",", cache, ")")
		} else {
			// If it is not my own ip then use Target Address to get link information
			// meaning NS came from peer for my ip Address
			debug.Logger.Debug("NS: Searching for link informating using TargetAddress:",
				ndInfo.TargetAddress.String())
			link, found := p.GetLink(ndInfo.TargetAddress.String())
			if !found {
				return nil, errors.New("No link found for:" + ndInfo.TargetAddress.String())
			}
			cache, exists := link.NbrCache[srcIP.String()]
			if exists {
				// @TODO: need to do something like updating timer or what not
				// update information to STALE, as update will be changed to reachable on
				// NA packet going out from my link
				cache.State = STALE
			} else {
				// This is a new cache entry.. so lets do Init
				cache.InitCache(link.ReachableTime, link.RetransTimer, srcIP.String(),
					ndInfo.TargetAddress.String(), link.PortIfIndex, p.PktCh)
				// In this case check for Source Link Layer Option... if specified then mark the state as
				// reachable and create neighbor entry in the platform... which means that
				// we are not waiting for NA packet anymore and proceeding with creating an
				// neighbor entry in the hardware
				if len(ndInfo.Options) > 0 {
					for _, option := range ndInfo.Options {
						if option.Type == NDOptionTypeSourceLinkLayerAddress {
							cache.State = REACHABLE
							mac := net.HardwareAddr(option.Value)
							cache.LinkLayerAddress = mac.String()
						}
					}
				} else {
					// state is moved to incomplete because neighbor is trying to
					// solicitate our ip address
					cache.State = INCOMPLETE
				}
			}
			debug.Logger.Debug("PEERNS: nbrCach (key, value) ---> (", srcIP.String(), ",", cache, ")")
			link.NbrCache[srcIP.String()] = cache
			p.SetLink(ndInfo.TargetAddress.String(), link)
		}
	}
	return ndInfo, nil
}

/*
 * From eth, ipv6 and ndInfo populate neighbor information for programming chip
 */
func (p *Packet) GetNbrInfoUsingNSPkt(eth *layers.Ethernet, v6hdr *layers.IPv6, ndInfo *NDInfo) config.NeighborInfo {
	nbrInfo := config.NeighborInfo{}
	var entry NeighborCache
	var exists bool
	// Update nbrInfo with state & pkt operation type
	// During Neighbor Solicitation we will use srcIP to get link Information
	link, found := p.GetLink(v6hdr.SrcIP.String())
	if found {
		entry, exists = link.NbrCache[ndInfo.TargetAddress.String()]
	} else {
		// You might have received solicitation from peer side...use that to get the state info
		link, found = p.GetLink(ndInfo.TargetAddress.String())
		if !found {
			nbrInfo.PktOperation = byte(PACKET_DROP)
			debug.Logger.Debug("dropping incoming neighbor solicitation as no link found")
			return nbrInfo
		}
		// find cache entry using src ip as the solicitation came from neighbor
		entry, exists = link.NbrCache[v6hdr.SrcIP.String()]
	}
	if exists {
		nbrInfo.State = entry.State
		if entry.LinkLayerAddress != "" {
			nbrInfo.MacAddr = entry.LinkLayerAddress
		} else {
			nbrInfo.MacAddr = eth.DstMAC.String()
		}
		nbrInfo.IpAddr = entry.IpAddr
		nbrInfo.IfIndex = link.PortIfIndex
	} else {
		nbrInfo.PktOperation = byte(PACKET_DROP)
		debug.Logger.Debug("dropping incoming neighbor solicitation as no nbr found for link", link)
	}
	return nbrInfo
}
