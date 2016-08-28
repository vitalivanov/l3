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
	"l3/ndp/packet"
	"sync"
	"time"
	"utils/asicdClient" // this is switch plugin need to change the name
)

type RxPktInfo struct {
	pkt     gopacket.Packet
	ifIndex int32
}

type NdpConfig struct {
	Vrf               string
	ReachableTime     uint32
	RetransTime       uint32
	RaRestransmitTime uint8
}

type NDPServer struct {
	NdpConfig
	SwitchPlugin asicdClient.AsicdClientIntf

	// System Ports information, key is IntfRef
	PhyPort             map[int32]config.PortInfo        // key is l2 ifIndex
	L3Port              map[int32]Interface              // key is l3 ifIndex
	VlanInfo            map[int32]config.VlanInfo        // key is vlanId
	VlanIfIdxVlanIdMap  map[int32]int32                  //reverse map for ifIndex ----> vlanId, used during ipv6 neig create
	SwitchMacMapEntries map[string]struct{}              // cache entry for all mac addresses on a switch
	NeighborInfo        map[string]config.NeighborConfig // neighbor created by NDP used for STATE
	neighborKey         []string                         // keys for all neighbor entries is stored here for GET calls

	//Configuration Channels
	GlobalCfg chan NdpConfig
	// Lock for reading/writing NeighorInfo
	// We need this lock because getbulk/getentry is not requested on the main entry point channel, rather it's a
	// direct call to server. So to avoid updating the Neighbor Runtime Info during read
	// it's better to use lock
	NeigborEntryLock *sync.RWMutex

	// Physical Port/ L2 Port State Notification
	PhyPortStateCh chan *config.PortState
	//IPV6 Create/Delete Notification Channel
	IpIntfCh chan *config.IPIntfNotification
	// IPv6 Up/Down Notification Channel
	IpStateCh chan *config.StateNotification
	// Vlan Create/Delete/Update Notification Channel
	VlanCh chan *config.VlanNotification
	//Received Pkt Channel
	RxPktCh chan *RxPktInfo
	//Package packet informs server over PktDataCh saying that send this packet..
	PktDataCh chan config.PacketData

	ndpIntfStateSlice     []int32
	ndpUpIntfStateSlice   []int32
	ndpL3IntfStateSlice   []int32
	ndpUpL3IntfStateSlice []int32

	//Pcap Default config values
	SnapShotLen int32
	Promiscuous bool
	Timeout     time.Duration

	// Neighbor Cache Information
	Packet *packet.Packet

	// @HACK: Need to find better way of getting Switch Mac Address
	SwitchMac string

	// Notification Channel for Publisher
	notifyChan chan<- []byte
}

const (
	NDP_SERVER_MAP_INITIAL_CAP = 50
	INTF_REF_NOT_FOUND         = "Not Found"
)
