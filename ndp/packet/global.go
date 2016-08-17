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
	"time"
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

type ParentLinkInfo struct {
	IfIndex  int32
	IpAddr   string
	ReturnCh chan config.PacketData
}

type NeighborCache struct {
	BaseReachableTimer   float32
	RetransTimerConfig   uint32
	ReachableTimeConfig  uint32
	RecomputeBaseTimer   *time.Timer
	ReachableTimer       *time.Timer
	RetransTimer         *time.Timer
	DelayFirstProbeTimer *time.Timer
	ProbesSent           uint8
	State                int
	LinkLayerAddress     string // this is our neighbor port mac address
	IpAddr               string
	MyLinkInfo           *ParentLinkInfo
}

type Link struct {
	NbrCache         map[string]NeighborCache
	PortIfIndex      int32
	LinkLocalAddress string // This is our link local mac address
	RetransTimer     uint32 // User should enter the value in mili-seconds
	ReachableTime    uint32 // @TODO for future
}

type Packet struct {
	PktCh chan config.PacketData
	// Neighbor Cache Information
	// This is map of string to link with (map of string to NeighborCache). Each key of the outer map is the our own
	// IP Address with its own Neigbor's map. Each inner map key is a Neighbor IP Address. Each inner map
	// expression retrieve the information pertaining to that neighbor
	LinkInfo map[string]Link
}

const (
	HOP_LIMIT                              = 255
	ICMPV6_CODE                            = 0
	ICMP_HDR_LENGTH                        = 8
	UNSPECIFIED_IP_ADDRESS                 = "::"
	IPV6_ICMPV6_MULTICAST_DST_MAC          = "33:33:00:00:00:00"
	IPV6_ADDRESS_BYTES                     = 16
	IPV6_MULTICAST_BYTE             byte   = 0xff
	IPV6_VERSION                    byte   = 6
	ICMPV6_MIN_LENGTH               uint16 = 24
	ICMPV6_NEXT_HEADER              byte   = 58
	ICMPV6_SOURCE_LINK_LAYER_LENGTH uint16 = 8
	SOLICITATED_NODE_ADDRESS               = "ff02::1:ff00:0000"
	SOLICITATED_SRC_IP                     = "::"
	MAX_UNICAST_SOLICIT             uint8  = 3
	MAX_MULTICAST_SOLICIT                  = 3
	MAX_ANYCAST_DELAY_TIMER                = 1
	MAX_NEIGHBOR_ADVERTISEMENT             = 3
	DELAY_FIRST_PROBE_TIME                 = 5 // this is in seconds
	MIN_RANDOM_FACTOR                      = 0.5
	MAX_RANDOM_FACTOR                      = 1.5
	RECOMPUTE_BASE_REACHABLE_TIMER         = 1 // this is in hour

	// Router Advertisement Specific Constants
	ICMPV6_MIN_LENGTH_RA         uint16 = 16
	ICMPV6_MIN_PAYLOAD_LENGTH_RA        = 12
)
