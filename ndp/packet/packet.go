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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"l3/ndp/packet/rx"
	"net"
)

/*
 *			ICMPv6 MESSAGE FORMAT
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Type      |     Code      |          Checksum             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           Reserved                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +                                                               +
 *   |                                                               |
 *   +                       Target Address                          +
 *   |                                                               |
 *   +                                                               +
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Options ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-
 *
 *  API: given a packet it will fill in ip header and icmpv6
 */
func getIpAndICMPv6Hdr(pkt gopacket.Packet, ipv6Hdr *layers.IPv6, icmpv6Hdr *layers.ICMPv6) error {
	ipLayer := pkt.Layer(layers.LayerTypeIPv6)
	if ipLayer == nil {
		return errors.New("Invalid IPv6 layer")
	}
	*ipv6Hdr = *ipLayer.(*layers.IPv6)
	ipPayload := ipLayer.LayerPayload()
	icmpv6Hdr.DecodeFromBytes(ipPayload, nil)
	return nil
}

func validateIPv6Hdr(hdr *layers.IPv6) error {
	if hdr.HopLimit != HOP_LIMIT {
		return errors.New(fmt.Sprintln("Invalid Hop Limit", hdr.HopLimit))
	}
	if hdr.Length < ICMPv6_MIN_LENGTH {
		return errors.New(fmt.Sprintln("Invalid ICMP length", hdr.Length))
	}
	return nil
}

func calculateChecksum(content []byte) uint16 {
	var csum uint32
	for i := 0; i < len(content); i += 2 {
		csum += uint32(content[i]) << 8
		csum += uint32(content[i+1])
	}
	return ^uint16((csum >> 16) + csum)
}

/*
 *	          ICMPv6 PSEUDO-HDR MESSAGE FORMAT
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                         Source Address                        +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                      Destination Address                      +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Upper-Layer Packet Length                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      zero                     |  Next Header  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
func validateChecksum(ipHdr *layers.IPv6, icmpv6Hdr *layers.ICMPv6) error {
	var buf []byte
	/*
	 *   PSEUDO HEADER BYTE START
	 */
	buf = append(buf, ipHdr.SrcIP...)
	buf = append(buf, ipHdr.DstIP...)
	buf = append(buf, 0)
	buf = append(buf, 0)
	buf = append(buf, byte((ICMP_HDR_LENGTH+len(icmpv6Hdr.LayerPayload()))/256))
	buf = append(buf, byte((ICMP_HDR_LENGTH+len(icmpv6Hdr.LayerPayload()))%256))
	buf = append(buf, 0)
	buf = append(buf, 0)
	buf = append(buf, 0)
	buf = append(buf, ICMP_PSEUDO_NEXT_HEADER)
	/*
	 *   PSEUDO HEADER BYTE END
	 */

	/*
	 *   ICMPv6 HEADER BYTE START
	 */
	buf = append(buf, icmpv6Hdr.TypeCode.Type())
	buf = append(buf, icmpv6Hdr.TypeCode.Code())
	//Adding zero bytes for calculateChecksum (2 bytes) and reserved (4 bytes)
	for idx := 0; idx < 6; idx++ {
		buf = append(buf, 0)
	}
	buf = append(buf, icmpv6Hdr.LayerPayload()...)
	// Pad to the next 32-bit boundary
	for idx := 0; idx < 4-(len(icmpv6Hdr.LayerPayload())/4); idx++ {
		buf = append(buf, 0)
	}
	/*
	 *   ICMPv6 HEADER BYTE END
	 */

	rv := calculateChecksum(buf)
	if rv != icmpv6Hdr.Checksum {
		return errors.New(fmt.Sprintf("Calculated Checksum 0x%x and wanted checksum is 0x%x",
			rv, icmpv6Hdr.Checksum))
	}
	return nil
}

func validateICMPv6Hdr(hdr *layers.ICMPv6, srcIP net.IP, dstIP net.IP) error {
	nds := &rx.NDSolicitation{}
	typeCode := hdr.TypeCode
	if typeCode.Code() != ICMPv6_CODE {
		return errors.New(fmt.Sprintln("Invalid Code", typeCode.Code()))
	}
	switch typeCode.Type() {
	case layers.ICMPv6TypeNeighborSolicitation:
		rx.DecodeNDSolicitation(hdr.LayerPayload(), nds)
		if rx.IsNDSolicitationMulticastAddr(nds.TargetAddress) {
			return errors.New(fmt.Sprintln("Targent Address specified", nds.TargetAddress,
				"is a multicast address"))
		}
		err := rx.ValidateIpAddrs(srcIP, dstIP)
		if err != nil {
			return err
		}

	case layers.ICMPv6TypeRouterSolicitation:
		return errors.New("Router Solicitation is not yet supported")
	}
	return nil
}

/* API: Get IPv6 & ICMPv6 Header
 *      Does Validation of IPv6
 *      Does Validation of ICMPv6
 * Validation Conditions are defined below, if anyone of them do not satisfy discard the packet:
 *  - The IP Hop Limit field has a value of 255, i.e., the packet
 *   could not possibly have been forwarded by a router. <- done
 *
 *  - ICMP Checksum is valid. <- done
 *
 *  - ICMP Code is 0. <- done
 *
 *  - ICMP length (derived from the IP length) is 24 or more octets. <- done
 *
 *  - Target Address is not a multicast address. <- done
 *
 *  - All included options have a length that is greater than zero. <- @TODO: need to add this later
 *
 *  - If the IP source address is the unspecified address, the IP
 *    destination address is a solicited-node multicast address. <- done
 *
 *  - If the IP source address is the unspecified address, there is no
 *    source link-layer address option in the message. <- @TODO: need to be done later
 */
func Validate(pkt gopacket.Packet) error {
	// first decode ipv6 & icmpv6 header
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	var err error

	// First get ipv6 and icmp6 information
	err = getIpAndICMPv6Hdr(pkt, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		return err
	}

	// Validating ipv6 header
	err = validateIPv6Hdr(ipv6Hdr)
	if err != nil {
		return err
	}

	// Validating checksum received
	err = validateChecksum(ipv6Hdr, icmpv6Hdr)
	if err != nil {
		return err
	}

	// Validating icmpv6 header
	err = validateICMPv6Hdr(icmpv6Hdr, ipv6Hdr.SrcIP, ipv6Hdr.DstIP)
	if err != nil {
		return err
	}
	return nil
}
