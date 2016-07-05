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
	_ "errors"
	"fmt"
	"github.com/google/gopacket/pcap"
	"l3/ndp/config"
	"l3/ndp/debug"
)

/*
 * API: will return all system port information
 */
func (svr *NDPServer) GetPorts() {
	debug.Logger.Info("Get Port State List")
	portsInfo, err := svr.SwitchPlugin.GetAllPortState()
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Failed to get all ports from system, ERROR:", err))
		return
	}
	for _, obj := range portsInfo {
		port := config.PortInfo{
			IntfRef:   obj.IntfRef,
			IfIndex:   obj.IfIndex,
			OperState: obj.OperState,
			Name:      obj.Name,
		}
		pObj, err := svr.SwitchPlugin.GetPort(obj.Name)
		if err != nil {
			debug.Logger.Err(fmt.Sprintln("Getting mac address for",
				obj.Name, "failed, error:", err))
		} else {
			port.MacAddr = pObj.MacAddr
			port.Description = pObj.Description
		}
		svr.PhyPort[port.IfIndex] = port
	}

	debug.Logger.Info("Done with Port State list")
	return
}

/*
 * API: will return all system vlan information
 */
func (svr *NDPServer) GetVlans() {
	debug.Logger.Info("Get Vlan Information")

	// Get Vlan State Information
	vlansStateInfo, err := svr.SwitchPlugin.GetAllVlanState()
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Failed to get system vlan information, ERROR:", err))
		return
	}

	// Get Vlan Config Information
	vlansConfigInfo, err := svr.SwitchPlugin.GetAllVlan()
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Failed to get system vlan config information, ERROR:", err))
	}

	// Store untag port information
	for _, vlanConfig := range vlansConfigInfo {
		entry := svr.VlanInfo[vlanConfig.VlanId]
		entry.UntagPortsMap = make(map[int]bool)
		for _, untagIntf := range vlanConfig.UntagIfIndexList {
			entry.UntagPortsMap[int(untagIntf)] = true
		}
		svr.VlanInfo[vlanConfig.VlanId] = entry
	}

	// store vlan state information like name, ifIndex, operstate
	for _, vlanState := range vlansStateInfo {
		entry, ok := svr.VlanInfo[vlanState.VlanId]
		if !ok {
			debug.Logger.Warning(fmt.Sprintln("config object for vlan", vlanState.VlanId, "not found"))
		}
		entry.Name = vlanState.VlanName
		entry.IfIndex = vlanState.IfIndex
		entry.OperState = vlanState.OperState
		svr.VlanInfo[vlanState.VlanId] = entry
	}
	return
}

/*
 * API: will return all system L3 interfaces information
 */
func (svr *NDPServer) GetIPIntf() {
	debug.Logger.Info("Get IPv6 Interface List")
	ipsInfo, err := svr.SwitchPlugin.GetAllIPv6IntfState()
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Failed to get all ipv6 interfaces from system, ERROR:", err))
		return
	}
	for _, obj := range ipsInfo {
		ipInfo := config.IPv6IntfInfo{
			IntfRef:   obj.IntfRef,
			IfIndex:   obj.IfIndex,
			OperState: obj.OperState,
			IpAddr:    obj.IpAddr,
		}
		svr.L3Port[ipInfo.IfIndex] = ipInfo
		svr.ndpL3IntfStateSlice = append(svr.ndpL3IntfStateSlice, ipInfo.IfIndex)
	}
	debug.Logger.Info("Done with IPv6 State list")
	return
}

/*
 * API: will create pcap handler for each port
 */
func (svr *NDPServer) CreatePcapHandler(name string, pHdl *pcap.Handle) error {
	// create pcap handler if there is none created right now
	if pHdl != nil {
		debug.Logger.Warning("Pcap already exists for port " + name)
		return nil //errors.New("Pcap already exists for port " + name)
	}
	pHdl, err := pcap.OpenLive(name, svr.SnapShotLen, svr.Promiscuous, svr.Timeout)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Creating Pcap Handler failed for", name, "Error:", err))
		return err
	}
	filter := "(ip6[6] == 0x3a) and (ip6[40] >= 133 && ip6[40] <= 137)"
	err = pHdl.SetBPFFilter(filter)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Creating BPF Filter failed Error", err))
		pHdl = nil
		return err
	}
	return err
}

/*
 * API: will delete pcap handler for each port
 */
func (svr *NDPServer) DeletePcapHandler(pHdl *pcap.Handle) {
	if pHdl != nil {
		pHdl.Close()
		pHdl = nil
	}
}

/*  API: will handle IPv6 notifications received from switch/asicd
 *      Msg types
 *	    1) Create:
 *		     Start Rx/Tx in this case
 *	    2) Delete:
 *		     Stop Rx/Tx in this case
 */
func (svr *NDPServer) HandleIPv6Notification(msg *config.IPv6IntfInfo) {
	switch msg.MsgType {
	case "CREATE":
		svr.StartRxTx(msg)
	case "DELETE":
		svr.StopRxTx(msg.IfIndex)
	}
}

/*
 *    API: It will remove any deleted ip port from the up state slice list
 */
func (svr *NDPServer) DeleteL3IntfFromUpState(ifIndex int32) {
	for idx, entry := range svr.ndpUpL3IntfStateSlice {
		if entry == ifIndex {
			//@TODO: need to optimize this
			svr.ndpUpL3IntfStateSlice = append(svr.ndpUpL3IntfStateSlice[:idx],
				svr.ndpUpL3IntfStateSlice[idx+1:]...)
			break
		}
	}
}
