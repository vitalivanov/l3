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
	"net"
	"reflect"
)

type NDSolicitation struct {
	Reserved      uint32
	TargetAddress net.IP
}

const (
	IPV6_ADDRESS_BYTES       = 16
	IPV6_MULTICAST_BYTE byte = 0xff
)

/*		ND Solicitation Packet Format Rcvd From ICPMv6
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
 */
func DecodeNDSolicitation(payload []byte, nds *NDSolicitation) error {
	nds.Reserved = uint32(binary.BigEndian.Uint32(payload[0:4]))
	if nds.TargetAddress == nil {
		nds.TargetAddress = make(net.IP, IPV6_ADDRESS_BYTES, IPV6_ADDRESS_BYTES)
	}
	copy(nds.TargetAddress, payload[4:20])
	return nil
}

/*
 *  According to RFC 2375 https://tools.ietf.org/html/rfc2375 all ipv6 multicast address have first byte as
 *  FF or 0xff, so compare that with the Target address first byte.
 */
func IsNDSolicitationMulticastAddr(in byte) bool {
	if reflect.DeepEqual(in, IPV6_MULTICAST_BYTE) {
		return true
	}
	return false
}
