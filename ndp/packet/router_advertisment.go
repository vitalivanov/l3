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
)

/*
 * Validate
 *	- All included options have a length that is greater than zero.
 *
 * Cache below information during validation
 *	- Source Link-Layer Address
 *	- Prefix Information
 *	- MTU options
 */
func (nd *NDInfo) ValidateRAInfo() error {
	options := nd.Options
	if len(options) > 0 {
		for _, option := range options {
			switch option.Type {
			case NDOptionTypeSourceLinkLayerAddress:
				if option.Length == 0 {
					return errors.New(fmt.Sprintln("During Router Advertisement",
						"Source Link Layer Option has length as zero"))
				}
			case NDOptionTypeMTU:
				if option.Length == 0 {
					return errors.New(fmt.Sprintln("During Router Advertisement",
						"MTU Option has length as zero"))
				}
			}
		}
	}
	return nil
}

/*
 * When we get router advertisement packet we need to update the mac address of peer and move the state to
 * REACHABLE
 *
 * Based on ifIndex we will get a prefixLink which contains all the prefixes for that link
 *
 * fill the NDInfo and then return it back to caller
 */
func (p *Packet) HandleRAMsg(hdr *layers.ICMPv6, srcIP, dstIP net.IP, ifIndex int32) (*NDInfo, error) {
	prefixFound := false
	ndInfo := &NDInfo{}
	ndInfo.DecodeRAInfo(hdr.TypeBytes, hdr.LayerPayload())
	err := ndInfo.ValidateRAInfo()
	if err != nil {
		return ndInfo, err
	}
	prefixLink, exists := p.GetLinkPrefix(ifIndex)
	if !exists {
		return nil, errors.New(fmt.Sprintln("No Prefix found for ifIndex:", ifIndex))
	}

	// iterate over prefix list and update the information
	for _, prefix := range prefixLink.PrefixList {
		// check if this is the prefix I am looking for or not
		if prefix.IpAddr == srcIP.String() {
			prefixFound = true
			// @TODO: jgheewala add this support
			// update timer value with received Router Lifetime
		}
	}

	// if Prefix is found then we will return from here
	if prefixFound {
		return ndInfo, nil
	}

	// if no prefix is found then lets create a new entry
	prefix := PrefixInfo{}
	var mac string
	for _, option := range ndInfo.Options {
		if option.Type == NDOptionTypeSourceLinkLayerAddress {
			macAddr := net.HardwareAddr(option.Value)
			mac = macAddr.String()
			break
		}
	}
	prefix.InitPrefix(srcIP.String(), mac, ndInfo.RouterLifetime)
	prefixLink.PrefixList = append(prefixLink.PrefixList, prefix)
	return ndInfo, nil
}

/*
 * From eth, ipv6 and ndInfo populate neighbor information for programming chip
 */
func (p *Packet) GetNbrInfoUsingRAPkt(eth *layers.Ethernet, v6hdr *layers.IPv6,
	ndInfo *NDInfo) (nbrInfo config.NeighborInfo) {

	if ndInfo.RouterLifetime == 0 {
		// @TODO: mark this entry for delete
	}
	// by default all RA Pkt are marked as reachable, is this correct??
	nbrInfo.State = REACHABLE
	// @TODO: can we use eth layer for mac Address ???
	nbrInfo.MacAddr = eth.SrcMAC.String()
	nbrInfo.IpAddr = v6hdr.SrcIP.String()

	return nbrInfo
}

/*
 *  Router Advertisement Packet
 */
func ConstructRAPacket(srcMac, dstMac, srcIP, dstIP string) []byte {

	// Ethernet Layer Information
	srcMAC, _ := net.ParseMAC(srcMac)
	dstMAC, _ := net.ParseMAC(dstMac)

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	debug.Logger.Debug("ethernet layer is", *eth)

	// IPv6 Layer Information
	sip := net.ParseIP(srcIP)
	dip := net.ParseIP(dstIP)

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
	payload := make([]byte, ICMPV6_MIN_LENGTH_RA)
	payload[0] = byte(layers.ICMPv6TypeRouterAdvertisement)
	payload[1] = byte(0)
	binary.BigEndian.PutUint16(payload[2:4], 0) // Putting zero for checksum before calculating checksum
	payload[4] = byte(64)
	payload[5] = byte(0)
	binary.BigEndian.PutUint16(payload[6:8], 1800) // Router Lifetime
	binary.BigEndian.PutUint32(payload[8:12], 0)   // reachable time
	binary.BigEndian.PutUint32(payload[12:16], 0)  // retrans time

	// Append Source Link Layer Option here
	srcOption := NDOption{
		Type:   NDOptionTypeSourceLinkLayerAddress,
		Length: 1,
		Value:  srcMAC,
	}

	mtuOption := NDOption{
		Type:   NDOptionTypeMTU,
		Length: 1,
		Value:  []byte{0x00, 0x00, 0x05, 0xdc},
	}
	payload = append(payload, byte(srcOption.Type))
	payload = append(payload, srcOption.Length)
	payload = append(payload, srcOption.Value...)

	payload = append(payload, byte(mtuOption.Type))
	payload = append(payload, mtuOption.Length)
	payload = append(payload, mtuOption.Value...)
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
