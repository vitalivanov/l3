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
	"l3/ndp/packet/rx"
	"net"
)

const (
	ICMP_HDR_LENGTH = 8
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

/*
 * Validation Conditions are defined below, if anyone of them do not satisfy discard the packet:
 *  - The IP Hop Limit field has a value of 255, i.e., the packet
 *   could not possibly have been forwarded by a router. <- done
 *
 *  - ICMP Checksum is valid.
 *
 *  - ICMP Code is 0. <- done
 *
 *  - ICMP length (derived from the IP length) is 24 or more octets. <- done
 *
 *  - Target Address is not a multicast address. <- done
 *
 *  - All included options have a length that is greater than zero.
 *
 *  - If the IP source address is the unspecified address, the IP
 *    destination address is a solicited-node multicast address. <- done
 *
 *  - If the IP source address is the unspecified address, there is no
 *    source link-layer address option in the message. <- @TODO: need to be done later
 */
func validateIPv6Hdr(hdr *layers.IPv6) error {
	if hdr.HopLimit != HOP_LIMIT {
		return errors.New(fmt.Sprintln("Invalid Hop Limit", hdr.HopLimit))
	}
	if hdr.Length < ICMPv6_MIN_LENGTH {
		return errors.New(fmt.Sprintln("Invalid ICMP length", hdr.Length))
	}
	return nil
}

type ICMPv6PseudoHeader struct {
	SrcIP      net.IP
	DstIP      net.IP
	Length     []byte
	NextHeader []byte
}

func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

func validateChecksum(ipHdr *layers.IPv6, icmpv6Hdr *layers.ICMPv6) error {
	var buf []byte
	//var chksumlen uint32
	//buf := []byte{icmpv6Hdr.TypeCode.Type(), icmpv6Hdr.TypeCode.Code(), 0, 0}
	pseudo := ICMPv6PseudoHeader{
		SrcIP: ipHdr.SrcIP,
		DstIP: ipHdr.DstIP,
	}
	pseudo.Length = make([]byte, 4, 4)
	pseudo.NextHeader = make([]byte, 4, 4)
	binary.BigEndian.PutUint32(pseudo.Length, uint32(len(icmpv6Hdr.LayerPayload())))
	binary.BigEndian.PutUint32(pseudo.NextHeader, uint32(ipHdr.NextHeader))
	buf = append(buf, pseudo.SrcIP...)
	buf = append(buf, pseudo.DstIP...)
	buf = append(buf, pseudo.Length...)
	buf = append(buf, pseudo.NextHeader...)
	buf = append(buf, icmpv6Hdr.TypeCode.Type())
	buf = append(buf, icmpv6Hdr.TypeCode.Code())
	buf = append(buf, 0) // checksum
	buf = append(buf, icmpv6Hdr.LayerPayload()...)
	// Pad to the next 16-bit boundary
	for idx := 0; idx < len(icmpv6Hdr.LayerPayload())%2; idx++ {
		buf = append(buf, 0)
	}
	/*
		chksumlen = 0
		for idx := 0; idx < len(buf); idx += 2 {
			chksumlen += uint32(buf[idx] << 8)
			if idx+1 < len(buf) {
				chksumlen += uint32(buf[idx+1])
			}
		}
		rv := ^uint16((chksumlen >> 16) + chksumlen)
	*/

	rv := checksum(buf)
	if rv != icmpv6Hdr.Checksum {
		return errors.New(fmt.Sprintln("Calculated Checksum", rv,
			"is different then recevied Checksum", icmpv6Hdr.Checksum))
	}
	return nil
}

func validateICMPv6Hdr(hdr *layers.ICMPv6, srcIP net.IP, dstIP net.IP) error {
	nds := &rx.NDSolicitation{}
	typeCode := hdr.TypeCode
	if typeCode.Code() != ICMPv6_CODE {
		return errors.New(fmt.Sprintln("Invalid Code", typeCode.Code()))
	}
	/*
		cksum, err := hdr.ComputeChecksum()
		if err != nil {
			return err
		}
		if cksum != hdr.Checksum {
			return errors.New(fmt.Sprintln("Mismatch in checksum, got:", cksum, "want:", hdr.Checksum))
		}
	*/
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
 */
func Validate(pkt gopacket.Packet) error {
	// first decode ipv6 & icmpv6 header
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	var err error
	err = getIpAndICMPv6Hdr(pkt, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		return err
	}
	err = validateIPv6Hdr(ipv6Hdr)
	if err != nil {
		return err
	}
	err = validateICMPv6Hdr(icmpv6Hdr, ipv6Hdr.SrcIP, ipv6Hdr.DstIP)
	return nil
}
