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
package flexswitch

import (
	"errors"
	"l3/ndp/api"
	"l3/ndp/config"
	"ndpd"
	"strconv"
)

func (h *ConfigHandler) CreateNDPGlobal(config *ndpd.NDPGlobal) (bool, error) {
	return api.CreateGlobalConfig(config.Vrf, uint32(config.RetransmitInterval), uint32(config.ReachableTime),
		uint8(config.RouterAdvertisementInterval))
}

func (h *ConfigHandler) UpdateNDPGlobal(orgCfg *ndpd.NDPGlobal, newCfg *ndpd.NDPGlobal, attrset []bool, op []*ndpd.PatchOpInfo) (bool, error) {
	return true, nil
}

func (h *ConfigHandler) DeleteNDPGlobal(config *ndpd.NDPGlobal) (bool, error) {
	return false, errors.New("Delete of Global Object is not supported")
}

/*
	IpAddr         string `SNAPROUTE: "KEY", ACCESS:"r", MULTIPLICITY:"*", DESCRIPTION: "Neighbor's IP Address"`
	MacAddr        string `DESCRIPTION: "MAC address of the neighbor machine with corresponding IP Address"`
	Vlan           string `DESCRIPTION: "Vlan ID of the Router Interface to which neighbor is attached to"`
	Intf           string `DESCRIPTION: "Router Interface to which neighbor is attached to"`
	ExpiryTimeLeft string `DESCRIPTION: "Time left before entry expires in case neighbor departs"`
*/

func convertNDPEntryStateToThriftEntry(state config.NeighborConfig) *ndpd.NDPEntryState {
	entry := ndpd.NewNDPEntryState()
	entry.IpAddr = state.IpAddr
	entry.MacAddr = state.MacAddr
	entry.Vlan = strconv.Itoa(int(state.VlanId))
	entry.Intf = state.Intf
	entry.IfIndex = state.IfIndex
	entry.ExpiryTimeLeft = state.ExpiryTimeLeft

	return entry
}

func (h *ConfigHandler) GetBulkNDPEntryState(fromIdx ndpd.Int, count ndpd.Int) (*ndpd.NDPEntryStateGetInfo, error) {
	nextIdx, currCount, ndpEntries := api.GetAllNeigborEntries(int(fromIdx), int(count))
	if len(ndpEntries) == 0 || ndpEntries == nil {
		return nil, errors.New("No Neighbor Found")
	}
	ndpResp := make([]*ndpd.NDPEntryState, len(ndpEntries))
	for idx, ndpEntry := range ndpEntries {
		ndpResp[idx] = convertNDPEntryStateToThriftEntry(ndpEntry)
	}
	ndpEntryBulk := ndpd.NewNDPEntryStateGetInfo()
	ndpEntryBulk.StartIdx = fromIdx
	ndpEntryBulk.EndIdx = ndpd.Int(nextIdx)
	ndpEntryBulk.Count = ndpd.Int(currCount)
	ndpEntryBulk.More = (nextIdx != 0)
	ndpEntryBulk.NDPEntryStateList = ndpResp
	return ndpEntryBulk, nil
}

func (h *ConfigHandler) GetNDPEntryState(ipAddr string) (*ndpd.NDPEntryState, error) {
	ndpEntry := api.GetNeighborEntry(ipAddr)
	if ndpEntry == nil {
		return nil, errors.New("No Neighbor Found for Ip Address:" + ipAddr)
	}
	return convertNDPEntryStateToThriftEntry(*ndpEntry), nil
}
