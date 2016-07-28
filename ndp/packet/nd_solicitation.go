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
	"net"
)

/*
 *
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
					return errors.New(fmt.Sprintln("During ND Solicitation with Unspecified address",
						"Source Link Layer Option should not be set"))
				}
			}
		}
	}
	return nil
}

/*
 *  Generic API to create Neighbor Solicitation Packet based on inputs..
 */
func ConstructNSPacket(targetAddr, srcIP, srcMac, dstMac string, ip net.IP) []byte {
	/* Entry exists so lets send out Neighbor Solicitation with "::" as srcIP and dstIP as
	 * Solicitated Multicast Address.
	 * Solicitated Muticast Address is formed by:
	 *	    Taking lower 24 bits or 3 bytes of an address (unicast or anycast) and appending those
	 *	    bits or bytes to the prefix of Solicitated-Node Address FF02:0:0:0:0:1:FFXX:XXXX
	 */
	dstIP := SOLICITATED_NODE_ADDRESS
	ip = ip.To16()
	for idx := (len(ip) - 3); idx < len(ip); idx++ {
		dstIP[idx] = ip[idx]
	}
	// Ethernet Layer Information
	srcMAC, _ := net.ParseMAC(srcMac)
	dstMAC, _ := net.ParseMAC(dstMac)
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	// IPv6 Layer Information
	ipv6 := &layers.IPv6{
		Version:      IPV6_VERSION,
		TrafficClass: 0,
		NextHeader:   layers.IPProtocolICMPv6,
		SrcIP:        net.ParseIP(srcIP),
		DstIP:        dstIP,
		HopLimit:     HOP_LIMIT,
	}

	// ICMPV6 Layer Information
	payload := make([]byte, ICMPV6_MIN_LENGTH)
	payload[0] = byte(layers.ICMPv6TypeNeighborSolicitation)
	payload[1] = byte(0)
	binary.BigEndian.PutUint16(payload[2:4], 0) // Putting zero for checksum before calculating checksum
	binary.BigEndian.PutUint32(payload[4:], 0)  // RESERVED FLAG...
	copy(payload[8:], ip)                       // Copy 16 Bytes of IPV6 address

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

	// GoPacket serialized buffer that will be used to send out raw bytes
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buffer, options, eth, ipv6, gopacket.Payload(payload))
	return buffer.Bytes()
}

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
		cache, exists := p.NbrCache[ndInfo.TargetAddress.String()]
		if exists {
			// @TODO: need to do something like updating timer or what not
		}
		// In this case check for Source Link Layer Option... if specified then mark the state as
		// reachable and create neighbor entry in the platform
		if len(ndInfo.Options) > 0 {
			for _, option := range ndInfo.Options {
				if option.Type == NDOptionTypeSourceLinkLayerAddress {
					cache.State = REACHABLE
					mac := net.HardwareAddr(option.Value)
					cache.LinkLayerAddress = mac.String()
				}
			}
		} else {
			cache.State = INCOMPLETE
		}
		p.NbrCache[ndInfo.TargetAddress.String()] = cache
	}
	return ndInfo, nil
}
