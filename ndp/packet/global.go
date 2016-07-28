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
	"l3/ndp/config"
)

type PACKET_OPERATION byte

const (
	PACKET_DROP                  PACKET_OPERATION = 1
	PACKET_PROCESS               PACKET_OPERATION = 2
	PACKET_FAILED_VALIDATION     PACKET_OPERATION = 3
	NEIGBOR_SOLICITATED_PACKET   PACKET_OPERATION = 4
	NEIGBOR_ADVERTISEMENT_PACKET PACKET_OPERATION = 5
)

const (
	_ = iota
	INCOMPLETE
	REACHABLE
	STALE
	DELAY
	PROBE
)

type NDOptionType byte

const (
	NDOptionTypeSourceLinkLayerAddress NDOptionType = 1
	NDOptionTypeTargetLinkLayerAddress NDOptionType = 2
	NDOptionTypePrefixInfo             NDOptionType = 3
	NDOptionTypeRedirectHeader         NDOptionType = 4
	NDOptionTypeMTU                    NDOptionType = 5
)

type NeighborCache struct {
	Timer            int // Future Info
	State            int
	LinkLayerAddress string // this is our neighbor port mac address
}

type Link struct {
	NbrCache         map[string]NeighborCache
	PortIfIndex      int32
	LinkLocalAddress string // This is our link local mac address
}

type Packet struct {
	PktCh chan config.PacketData
	//NbrCache map[string]NeighborCache
	// Neighbor Cache Information
	// This is map of string to (map of string to NeighborCache). Each key of the outer map is the our own
	// IP Address with its own Neigbor's map. Each inner map key is a Neighbor IP Address. Each inner map
	// expression retrieve the information pertaining to that neighbor
	LinkInfo map[string]Link //map[string]NeighborCache
	//Operation PACKET_OPERATION
}

const (
	HOP_LIMIT                              = 255
	ICMPV6_CODE                            = 0
	ICMP_HDR_LENGTH                        = 8
	UNSPECIFIED_IP_ADDRESS                 = "::"
	IPV6_ICMPV6_MULTICAST_DST_MAC          = "33:33:ff:00:00:00"
	IPV6_ADDRESS_BYTES                     = 16
	IPV6_MULTICAST_BYTE             byte   = 0xff
	IPV6_VERSION                    byte   = 6
	ICMPV6_MIN_LENGTH               uint16 = 24
	ICMPV6_NEXT_HEADER              byte   = 58
	ICMPV6_SOURCE_LINK_LAYER_LENGTH uint16 = 8
)

var SOLICITATED_NODE_ADDRESS = []byte{
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00,
}
