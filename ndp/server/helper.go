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
	"l3/ndp/config"
	"l3/ndp/debug"
	"utils/commonDefs"
)

/*
 * API: will return all system port information
 */
func (svr *NDPServer) GetPorts() {
	debug.Logger.Info("Get Port State List")
	portsInfo, err := svr.SwitchPlugin.GetAllPortState()
	if err != nil {
		debug.Logger.Err("Failed to get all ports from system, ERROR:", err)
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
			debug.Logger.Err("Getting mac address for", obj.Name, "failed, error:", err)
		} else {
			port.MacAddr = pObj.MacAddr
			port.Description = pObj.Description
		}
		l2Port := svr.L2Port[port.IfIndex]
		l2Port.Info = port
		l2Port.RX = nil
		//svr.PhyPort[port.IfIndex] = port
		svr.L2Port[port.IfIndex] = l2Port
		svr.SwitchMacMapEntries[port.MacAddr] = empty
		svr.SwitchMac = port.MacAddr // @HACK.... need better solution
	}

	debug.Logger.Info("Done with Port State list")
	return
}

/*
// Store tag port information
func (svr *NDPServer) addTagPorts(vlansConfigInfo []*commonDefs.Vlan) {
	for _, vlanConfig := range vlansConfigInfo {
		entry := svr.VlanInfo[vlanConfig.VlanId]
		entry.TagPortsMap = make(map[int32]bool)
		for _, tagIntf := range vlanConfig.IfIndexList {
			entry.TagPortsMap[tagIntf] = true
		}
		svr.VlanInfo[vlanConfig.VlanId] = entry
	}
}

// Store untag port information
func (svr *NDPServer) addUnTagPorts(vlansConfigInfo []*commonDefs.Vlan) {
	for _, vlanConfig := range vlansConfigInfo {
		entry := svr.VlanInfo[vlanConfig.VlanId]
		entry.untagportsmap = make(map[int32]bool)
		for _, untagintf := range vlanconfig.untagifindexlist {
			entry.untagportsmap[untagintf] = true
		}
		svr.VlanInfo[vlanConfig.VlanId] = entry
	}
}
*/

/*
 * API: will return all system vlan information
 */
func (svr *NDPServer) GetVlans() {
	debug.Logger.Info("Get Vlan Information")

	// Get Vlan State Information
	vlansStateInfo, err := svr.SwitchPlugin.GetAllVlanState()
	if err != nil {
		debug.Logger.Err("Failed to get system vlan information, ERROR:", err)
		return
	}

	// Get Vlan Config Information
	vlansConfigInfo, err := svr.SwitchPlugin.GetAllVlan()
	if err != nil {
		debug.Logger.Err("Failed to get system vlan config information, ERROR:", err)
	}
	//svr.addTagPorts(vlansConfigInfo)
	//svr.addUnTagPorts(vlansConfigInfo)
	// store vlan state information like name, ifIndex, operstate
	for _, vlanState := range vlansStateInfo {
		entry, _ := svr.VlanInfo[vlanState.IfIndex]
		//if !ok {
		//	debug.Logger.Warning("config object for vlan", vlanState.VlanId, "not found")
		//}
		entry.VlanId = vlanState.VlanId
		entry.VlanIfIndex = vlanState.IfIndex
		entry.Name = vlanState.VlanName
		entry.OperState = vlanState.OperState
		for _, vlanconfig := range vlansConfigInfo {
			if entry.VlanId == vlanconfig.VlanId {
				entry.UntagPortsMap = make(map[int32]bool)
				for _, untagintf := range vlanconfig.UntagIfIndexList {
					entry.UntagPortsMap[untagintf] = true
				}
				entry.TagPortsMap = make(map[int32]bool)
				for _, tagIntf := range vlanconfig.IfIndexList {
					entry.TagPortsMap[tagIntf] = true
				}
			}
		}
		svr.VlanInfo[vlanState.IfIndex] = entry
		svr.VlanIfIdxVlanIdMap[vlanState.VlanName] = vlanState.VlanId
		//svr.VlanInfo[vlanState.VlanId] = entry
		//svr.VlanIfIdxVlanIdMap[vlanState.VlanName] = vlanState.VlanId //cached the info for ipv6 neighbor create
	}
	debug.Logger.Info("Done with Vlan List")
	return
}

/*
 * API: will return all system L3 interfaces information
 */
func (svr *NDPServer) GetIPIntf() {
	debug.Logger.Info("Get IPv6 Interface List")
	ipsInfo, err := svr.SwitchPlugin.GetAllIPv6IntfState()
	if err != nil {
		debug.Logger.Err("Failed to get all ipv6 interfaces from system, ERROR:", err)
		return
	}
	for _, obj := range ipsInfo {
		// ndp will not listen on loopback interfaces
		if svr.SwitchPlugin.IsLoopbackType(obj.IfIndex) {
			continue
		}
		ipInfo, exists := svr.L3Port[obj.IfIndex]
		if !exists {
			ipInfo.InitIntf(obj, svr.PktDataCh, svr.NdpConfig)
			ipInfo.SetIfType(svr.GetIfType(obj.IfIndex))
			// cache reverse map from intfref to ifIndex, used mainly during state
			svr.L3IfIntfRefToIfIndex[obj.IntfRef] = obj.IfIndex
		} else {
			ipInfo.UpdateIntf(obj.IpAddr)
		}
		svr.L3Port[ipInfo.IfIndex] = ipInfo
		if !exists {
			svr.ndpL3IntfStateSlice = append(svr.ndpL3IntfStateSlice, ipInfo.IfIndex)
		}
	}
	debug.Logger.Info("Done with IPv6 State list")
	return
}

func (svr *NDPServer) GetIfType(ifIndex int32) int {
	debug.Logger.Info("get ifType for ifIndex:", ifIndex)
	if _, ok := svr.L2Port[ifIndex]; ok {
		debug.Logger.Info("L3 Port is of IfTypePort")
		return commonDefs.IfTypePort
	}

	if _, ok := svr.VlanInfo[ifIndex]; ok {
		debug.Logger.Info("L3 Port is of IfTypeVlan")
		return commonDefs.IfTypeVlan
	}
	debug.Logger.Info("no valid ifIndex found")
	return -1
}

/*  API: will handle IPv6 notifications received from switch/asicd
 *      Msg types
 *	    1) Create:
 *		    Create an entry in the map
 *	    2) Delete:
 *		    delete an entry from the map
 */
func (svr *NDPServer) HandleIPIntfCreateDelete(obj *config.IPIntfNotification) {
	ipInfo, exists := svr.L3Port[obj.IfIndex]
	switch obj.Operation {
	case config.CONFIG_CREATE:
		// Done during Init
		if exists {
			ipInfo.UpdateIntf(obj.IpAddr)
			svr.L3Port[obj.IfIndex] = ipInfo
			return
		}

		ipInfo = Interface{}
		ipInfo.CreateIntf(obj, svr.PktDataCh, svr.NdpConfig)
		ipInfo.SetIfType(svr.GetIfType(obj.IfIndex))
		svr.ndpL3IntfStateSlice = append(svr.ndpL3IntfStateSlice, ipInfo.IfIndex)
	case config.CONFIG_DELETE:
		if !exists {
			debug.Logger.Err("Got Delete request for non existing l3 port", obj.IfIndex)
			return
		}
		// stop rx/tx on the deleted interface
		debug.Logger.Info("Delete IP interface received for", ipInfo.IntfRef, "ifIndex:", ipInfo.IfIndex)
		deleteEntries := ipInfo.DeInitIntf()
		if len(deleteEntries) > 0 {
			svr.DeleteNeighborInfo(deleteEntries, obj.IfIndex)
		}
		// @TODO: need to take care for ifTYpe vlan
		//@TODO: need to remove ndp l3 interface from up slice, but that is taken care of by stop rx/tx
	}
	svr.L3Port[ipInfo.IfIndex] = ipInfo
}

/*  API: will handle l2/physical notifications received from switch/asicd
 *	  Update map entry and then call state notification
 *
 */
func (svr *NDPServer) HandlePhyPortStateNotification(msg *config.PortState) {
	debug.Logger.Info("Handling L2 Port State:", msg.IfState, "for ifIndex:", msg.IfIndex)
	svr.updateL2Operstate(msg.IfIndex, msg.IfState)
	/*
		l3Port, exists := svr.findL3Port(msg.IfIndex)
		if !exists {
			debug.Logger.Debug("Physical Port for ifIndex:", msg.IfIndex,
				"is not l3 port and ignoring port state notification")
			return
		}
	*/
	// search this ifIndex in l3 map to get the ifIndex -> ipAddr map
	/*
		switch msg.IfState {
		case config.STATE_UP:
			// if the port state is up, then we need to start RX/TX only for global scope ip address,
			// if it is not started
			//debug.Logger.Info("Create pkt handler for", msg.IfIndex, "GS:", l3Port.IpAddr, "LS:", l3Port.LinkLocalIp)
			//svr.StartRxTx(msg.IfIndex)
			svr.updateL2Operstate(msg.IfIndex, config.STATE_UP)

		case config.STATE_DOWN:
			// if the port state is down, then we need to delete all the neighbors for that ifIndex...which
			// includes deleting neighbor from link local ip address also
			//debug.Logger.Info("Stop receiving frames for", l3Port.IntfRef)
			svr.updateL2Operstate(msg.IfIndex, config.STATE_DOWN)
			//svr.StopRxTx(msg.IfIndex, "ALL")
		}
	*/
}

/*  API: will handle Vlan Create/Delete/Update notifications received from switch/asicd
 */
func (svr *NDPServer) HandleVlanNotification(msg *config.VlanNotification) {
	debug.Logger.Info("Handle Vlan Notfication:", msg.Operation, "for vlanId:", msg.VlanId, "vlan:", msg.VlanName,
		"vlanIfIndex:", msg.VlanIfIndex, "tagList:", msg.TagPorts, "unTagList:", msg.UntagPorts)
	vlan, exists := svr.VlanInfo[msg.VlanIfIndex]
	switch msg.Operation {
	case config.CONFIG_CREATE:
		debug.Logger.Info("Received Vlan Create:", *msg)
		svr.VlanIfIdxVlanIdMap[msg.VlanName] = msg.VlanId
		vlan.Name = msg.VlanName
		vlan.VlanId = msg.VlanId
		vlan.VlanIfIndex = msg.VlanIfIndex
		// Store untag port information
		for _, untagIntf := range msg.UntagPorts {
			if vlan.UntagPortsMap == nil {
				vlan.UntagPortsMap = make(map[int32]bool)
			}
			vlan.UntagPortsMap[untagIntf] = true
		}
		// Store untag port information
		for _, tagIntf := range msg.TagPorts {
			if vlan.TagPortsMap == nil {
				vlan.TagPortsMap = make(map[int32]bool)
			}
			vlan.TagPortsMap[tagIntf] = true
		}
		svr.VlanInfo[msg.VlanIfIndex] = vlan
	case config.CONFIG_DELETE:
		debug.Logger.Info("Received Vlan Delete:", *msg)
		if exists {
			vlan.UntagPortsMap = nil
			vlan.TagPortsMap = nil
			delete(svr.VlanInfo, msg.VlanIfIndex)
		}
	case config.CONFIG_UPDATE:
		//@TODO: jgheewala
		debug.Logger.Info("NEED TO SUPPORT Vlan Update:", *msg)
	}
}

/*  API: will handle IPv6 notifications received from switch/asicd
 *      Msg types
 *	    1) Create:
 *		     Start Rx/Tx in this case
 *	    2) Delete:
 *		     Stop Rx/Tx in this case
 */
func (svr *NDPServer) HandleStateNotification(msg *config.IPIntfNotification) {
	debug.Logger.Info("Handling L3 State:", msg.Operation, "for port:", msg.IntfRef, "ifIndex:", msg.IfIndex, "ipAddr:", msg.IpAddr)
	switch msg.Operation {
	case config.STATE_UP:
		debug.Logger.Info("Create pkt handler for port:", msg.IntfRef, "ifIndex:", msg.IfIndex, "IpAddr:", msg.IpAddr)
		svr.StartRxTx(msg.IfIndex)
	case config.STATE_DOWN:
		debug.Logger.Info("Delete pkt handler for port:", msg.IntfRef, "ifIndex:", msg.IfIndex, "IpAddr:", msg.IpAddr)
		svr.StopRxTx(msg.IfIndex, msg.IpAddr)
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
func (svr *NDPServer) PopulateVlanInfo(nbrInfo *config.NeighborConfig, intfRef string) {
	debug.Logger.Info("jgheewala: populate vlan info called for intfRef:", intfRef, "incoming vlan is", nbrInfo.VlanId)
	// check if the ifIndex is present in the reverse map..
	vlanId, exists := svr.VlanIfIdxVlanIdMap[intfRef]
	if exists {
		debug.Logger.Info("jgheewala: svr.VlanIfIdxVlanIdMap have entry for and hence new vlan is", vlanId)
		// if the entry exists then use the vlanId from reverse map
		nbrInfo.VlanId = vlanId
	} else {
		// @TODO: move this to plugin specific
		// in this case use system reserved Vlan id which is -1
		debug.Logger.Info("jgheewala: svr.VlanIfIdxVlanIdMap does not have entry for ifIndex:", intfRef,
			"hence new vlan is internal vlan")
		nbrInfo.VlanId = -1
	}
}

/*
 *    API: send ipv6 neighbor create notification
 */
func (svr *NDPServer) SendIPv6CreateNotification(ipAddr string, ifIndex int32) {
	msgBuf, err := createNotificationMsg(ipAddr, ifIndex)
	if err != nil {
		return
	}

	notification := commonDefs.NdpNotification{
		MsgType: commonDefs.NOTIFY_IPV6_NEIGHBOR_CREATE,
		Msg:     msgBuf,
	}
	debug.Logger.Info("Sending Create notification for ip address:", ipAddr, "and ifIndex:", ifIndex)
	svr.pushNotification(notification)
}

/*
 *    API: send ipv6 neighbor delete notification
 */
func (svr *NDPServer) SendIPv6DeleteNotification(ipAddr string, ifIndex int32) {
	msgBuf, err := createNotificationMsg(ipAddr, ifIndex)
	if err != nil {
		return
	}

	notification := commonDefs.NdpNotification{
		MsgType: commonDefs.NOTIFY_IPV6_NEIGHBOR_DELETE,
		Msg:     msgBuf,
	}
	debug.Logger.Info("Sending Delete notification for ip address:", ipAddr, "and ifIndex:", ifIndex)
	svr.pushNotification(notification)
}
