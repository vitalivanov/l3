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
	"github.com/google/gopacket"
)

/*
 * Validation Conditions are defined below:
 *  - The IP Hop Limit field has a value of 255, i.e., the packet
 *   could not possibly have been forwarded by a router.
 *
 *  - ICMP Checksum is valid.
 *
 *  - ICMP Code is 0.
 *
 *  - ICMP length (derived from the IP length) is 24 or more octets.
 *
 *  - Target Address is not a multicast address.
 *
 *  - All included options have a length that is greater than zero.
 *
 *  - If the IP source address is the unspecified address, the IP
 *    destination address is a solicited-node multicast address.
 *
 *  - If the IP source address is the unspecified address, there is no
 *    source link-layer address option in the message.
 */
func ValidateNdSolicitation(pkt gopacket.Packet) (valid bool) {
	// first decode ip packet

	return valid
}
