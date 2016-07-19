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

type RxPktInfo struct {
	pkt     gopacket.Packet
	ifIndex int32
}

type NDPServer struct {
	SwitchPlugin asicdClient.AsicdClientIntf

	// System Ports information, key is IntfRef
	PhyPort             map[int32]config.PortInfo      // key is l2 ifIndex
	L3Port              map[int32]config.IPv6IntfInfo  // key is l3 ifIndex
	VlanInfo            map[int32]config.VlanInfo      // key is vlanId
	VlanIfIdxVlanIdMap  map[int32]int32                //reverse map for ifIndex ----> vlanId, used during ipv6 neig create
	SwitchMacMapEntries map[string]struct{}            // cache entry for all mac addresses on a switch
	NeighborInfo        map[string]config.NeighborInfo // cache which neighbors are created by NDP

	// Physical Port/ L2 Port State Notification
	PhyPortStateCh chan *config.StateNotification
	//IPV6 Create/Delete Notification Channel
	IpIntfCh chan *config.IPIntfNotification
	// IPv6 Up/Down Notification Channel
	IpStateCh chan *config.StateNotification
	// Vlan Create/Delete/Update Notification Channel
	VlanCh chan *config.VlanNotification
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
	NDP_SERVER_MAP_INITIAL_CAP = 50
	INTF_REF_NOT_FOUND         = "Not Found"
)
