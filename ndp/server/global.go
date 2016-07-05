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
package server

import (
	"github.com/google/gopacket"
	"l3/ndp/config"
	"time"
	"utils/asicdClient" // this is switch plugin need to change the name
)

const (
	NDP_PORT_STATE_UP   = "UP"
	NDP_PORT_STATE_DOWN = "DOWN"
	NDP_IP_STATE_UP     = "UP"
	NDP_IP_STATE_DOWN   = "DOWN"
)

type RxPktInfo struct {
	pkt     gopacket.Packet
	ifIndex int32
}

type NDPServer struct {
	SwitchPlugin asicdClient.AsicdClientIntf

	// System Ports information, key is IntfRef
	PhyPort  map[int32]config.PortInfo
	L3Port   map[int32]config.IPv6IntfInfo
	VlanInfo map[int32]config.VlanInfo

	//IPV6 Create/Delete Notification Channel
	Ipv6Ch chan *config.IPv6IntfInfo
	//Received Pkt Channel
	RxPktCh chan *RxPktInfo

	ndpIntfStateSlice     []int32
	ndpUpIntfStateSlice   []int32
	ndpL3IntfStateSlice   []int32
	ndpUpL3IntfStateSlice []int32

	//Pcap Default config values
	SnapShotLen int32
	Promiscuous bool
	Timeout     time.Duration
}

const (
	NDP_SYSTEM_PORT_MAP_CAPACITY = 50
)
