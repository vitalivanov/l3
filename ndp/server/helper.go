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
	"net"
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
		var empty struct{}
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
		svr.SwitchMacMapEntries[port.MacAddr] = empty
		svr.SwitchMac = port.MacAddr // @HACK.... need better solution
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
		svr.VlanIfIdxVlanIdMap[vlanState.IfIndex] = vlanState.VlanId //cached the info for ipv6 neighbor create
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
func (svr *NDPServer) CreatePcapHandler(name string) (pHdl *pcap.Handle, err error) {
	pHdl, err = pcap.OpenLive(name, svr.SnapShotLen, svr.Promiscuous, svr.Timeout)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Creating Pcap Handler failed for", name, "Error:", err))
		return pHdl, err
	}
	filter := "(ip6[6] == 0x3a) and (ip6[40] >= 133 && ip6[40] <= 137)"
	err = pHdl.SetBPFFilter(filter)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Creating BPF Filter failed Error", err))
		pHdl = nil
		return pHdl, err
	}
	return pHdl, err
}

/*
 * API: will delete pcap handler for each port
 */
func (svr *NDPServer) DeletePcapHandler(pHdl **pcap.Handle) {
	if *pHdl != nil {
		(*pHdl).Close()
		*pHdl = nil
	}
}

/*
 *  API: given an ifIndex, it will search portMap (fpPort1, fpPort2, etc) to get the name or it will do
 *	 reverse search for vlanMap (vlan ifIndex ---> to vlanId) and from that we will get the name
 */
func (svr *NDPServer) GetIntfRefName(ifIndex int32) string {
	portEnt, exists := svr.PhyPort[ifIndex]
	if exists {
		return portEnt.Name
	}
	vlanId, exists := svr.VlanIfIdxVlanIdMap[ifIndex]
	if exists {
		vlanInfo, exists := svr.VlanInfo[vlanId]
		if exists {
			return vlanInfo.Name
		}
	}
	return INTF_REF_NOT_FOUND
}

func (svr *NDPServer) IsLinkLocal(ipAddr string) bool {
	ip, _, _ := net.ParseCIDR(ipAddr)
	return ip.IsLinkLocalUnicast() && (ip.To4() == nil)
}

func (svr *NDPServer) IsIPv6Addr(ipAddr string) bool {
	ip, _, _ := net.ParseCIDR(ipAddr)
	if ip.To4() == nil {
		return true
	}

	return false
}

/*  API: will handle IPv6 notifications received from switch/asicd
 *      Msg types
 *	    1) Create:
 *		    Create an entry in the map
 *	    2) Delete:
 *		    delete an entry from the map
 */
func (svr *NDPServer) HandleCreateIPIntf(obj *config.IPIntfNotification) {
	ipInfo, exists := svr.L3Port[obj.IfIndex]
	switch obj.Operation {
	case config.CONFIG_CREATE:
		defer svr.Packet.InitLink(obj.IfIndex, obj.IpAddr, svr.SwitchMac)
		if exists {
			if svr.IsLinkLocal(obj.IpAddr) {
				debug.Logger.Info(fmt.Sprintln("Updating link local Ip", obj.IpAddr, "for", obj.IfIndex))
				ipInfo.LinkLocalIp = obj.IpAddr
				svr.L3Port[obj.IfIndex] = ipInfo
				return
			}
			debug.Logger.Err(fmt.Sprintln("Received create notification for ifIndex", obj.IfIndex,
				"when entry already exist in the database. Dumping IpAddr for debugging info.",
				"Received Ip:", obj.IpAddr, "stored Ip:", ipInfo.IpAddr))
			return
		}
		ipInfo = config.IPv6IntfInfo{
			IfIndex: obj.IfIndex,
			IpAddr:  obj.IpAddr,
		}
		ipInfo.IntfRef = svr.GetIntfRefName(ipInfo.IfIndex)
		if ipInfo.IntfRef == INTF_REF_NOT_FOUND {
			debug.Logger.Alert(fmt.Sprintln("Couldn't find name for ifIndex:", ipInfo.IfIndex,
				"and hence pcap create will be failure"))
		}
		debug.Logger.Info(fmt.Sprintln("Created IP inteface", ipInfo.IntfRef, "ifIndex:", ipInfo.IfIndex))
		svr.L3Port[ipInfo.IfIndex] = ipInfo
		svr.ndpL3IntfStateSlice = append(svr.ndpL3IntfStateSlice, ipInfo.IfIndex)
	case config.CONFIG_DELETE:
		//@TODO: need to handle delete cases
	}
}

/*  API: will handle l2/physical notifications received from switch/asicd
 *	  Update map entry and then call state notification
 *
 */
func (svr *NDPServer) HandlePhyPortStateNotification(msg *config.StateNotification) {
	//@TODO: do we need to handle this case... i don't think so
}

/*  API: will handle IPv6 notifications received from switch/asicd
 *      Msg types
 *	    1) Create:
 *		     Start Rx/Tx in this case
 *	    2) Delete:
 *		     Stop Rx/Tx in this case
 */
func (svr *NDPServer) HandleStateNotification(msg *config.StateNotification) {
	debug.Logger.Info(fmt.Sprintln("Received State:", msg.State, "for ifIndex:", msg.IfIndex, "ipAddr:",
		msg.IpAddr))
	switch msg.State {
	case config.STATE_UP:
		if svr.IsIPv6Addr(msg.IpAddr) {
			if !svr.IsLinkLocal(msg.IpAddr) {
				debug.Logger.Info(fmt.Sprintln("Create pkt handler for", msg.IfIndex,
					"IpAddr:", msg.IpAddr))
				svr.StartRxTx(msg.IfIndex)
			}
		}
	case config.STATE_DOWN:
		if svr.IsIPv6Addr(msg.IpAddr) {
			svr.StopRxTx(msg.IfIndex)
		}
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

/*
 *    API: It will populate correct vlan information which will be used for ipv6 neighbor create
 */
func (svr *NDPServer) PopulateVlanInfo(nbrInfo *config.NeighborInfo, ifIndex int32) {
	// check if the ifIndex is present in the reverse map..
	vlanId, exists := svr.VlanIfIdxVlanIdMap[ifIndex]
	if exists {
		// if the entry exists then use the vlanId from reverse map
		nbrInfo.VlanId = vlanId
	} else {
		// @TODO: move this to plugin specific
		// in this case use system reserved Vlan id which is -1
		nbrInfo.VlanId = -1
	}
}
