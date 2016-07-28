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
package rx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	_ "reflect"
)

type NDOptionType byte

const (
	NDOptionTypeSourceLinkLayerAddress NDOptionType = 1
	NDOptionTypeTargetLinkLayerAddress NDOptionType = 2
	NDOptionTypePrefixInfo             NDOptionType = 3
	NDOptionTypeRedirectHeader         NDOptionType = 4
	NDOptionTypeMTU                    NDOptionType = 5
)

type NDOption struct {
	Type   NDOptionType
	Length byte
	Value  []byte
}

type NDInfo struct {
	TargetAddress net.IP
	Options       []*NDOption
}

const (
	IPV6_ADDRESS_BYTES       = 16
	IPV6_MULTICAST_BYTE byte = 0xff
)

/*		ND Solicitation Packet Format Rcvd From ICPMv6
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
 */

func DecodeOptionLayer(payload []byte) *NDOption {
	ndOpt := &NDOption{}
	ndOpt.Type = NDOptionType(payload[0])
	ndOpt.Length = payload[1]
	ndOpt.Value = append(ndOpt.Value, payload[2:]...)
	return ndOpt
}

func DecodeNDInfo(payload []byte, nds *NDInfo) error {
	if nds.TargetAddress == nil {
		nds.TargetAddress = make(net.IP, IPV6_ADDRESS_BYTES, IPV6_ADDRESS_BYTES)
	}
	copy(nds.TargetAddress, payload[0:IPV6_ADDRESS_BYTES])
	if len(payload) > IPV6_ADDRESS_BYTES {
		//decode option layer also
		ndOpt := DecodeOptionLayer(payload[IPV6_ADDRESS_BYTES:])
		nds.Options = append(nds.Options, ndOpt)
	}
	return nil
}

/*
 *  According to RFC 2375 https://tools.ietf.org/html/rfc2375 all ipv6 multicast address have first byte as
 *  FF or 0xff, so compare that with the Target address first byte.
 */
func IsTargetMulticast(in net.IP) bool {
	if in.IsMulticast() {
		return true
	}
	return false
}

/*
 *
 *  Range for Solicited Node Multicast Address from RFC 4291 FF02:0:0:0:0:1:FF00:0000 to FF02:0:0:0:0:1:FFFF:FFFF
 *  if srcIp == "::", i.e Unspecified address then dstIP should be solicited-node address FF02:0:0:0:0:1:FFXX:XXXX
 *  if srcIP == "::", then there should not be any source link-layer option in message
 */
func ValidateNDSInfo(srcIP net.IP, dstIP net.IP, options []*NDOption) error {
	if srcIP.IsUnspecified() {
		if !(dstIP[0] == IPV6_MULTICAST_BYTE && dstIP[1]&0x0f == 0x02 &&
			dstIP[11]&0x0f == 0x01 && dstIP[12] == IPV6_MULTICAST_BYTE) {
			return errors.New(fmt.Sprintln("Destination IP address",
				dstIP.String(), "is not Solicited-Node Multicast Address"))
		}
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
 * If the IP Destination Address is a multicast address the
 *       Solicited flag is zero.
 * All included options have a length that is greater than zero.
 */
func ValidateNDAInfo(icmpFlags []byte, dstIP net.IP) error {
	if dstIP.IsMulticast() {
		flags := binary.BigEndian.Uint16(icmpFlags[0:2])
		if (flags & 0x4000) == 0x4000 {
			return errors.New(fmt.Sprintln("Check for If Destination Address is a multicast address then",
				"the Solicited flag is zero, Failed"))
		}
	}
	// @TODO: need to add support for options length
	return nil
}
