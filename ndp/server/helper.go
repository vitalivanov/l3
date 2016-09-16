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
	"encoding/json"
	_ "errors"
	"l3/ndp/config"
	"l3/ndp/debug"
	"net"
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
		debug.Logger.Err("Failed to get system vlan information, ERROR:", err)
		return
	}

	// Get Vlan Config Information
	vlansConfigInfo, err := svr.SwitchPlugin.GetAllVlan()
	if err != nil {
		debug.Logger.Err("Failed to get system vlan config information, ERROR:", err)
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
			debug.Logger.Warning("config object for vlan", vlanState.VlanId, "not found")
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
		debug.Logger.Err("Failed to get all ipv6 interfaces from system, ERROR:", err)
		return
	}
	for _, obj := range ipsInfo {
		ipInfo, exists := svr.L3Port[obj.IfIndex]
		if !exists {
			ipInfo.InitIntf(obj, svr.PktDataCh, svr.NdpConfig)
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

/*
 *  API: given an ifIndex, it will search portMap (fpPort1, fpPort2, etc) to get the name or it will do
 *	 reverse search for vlanMap (vlan ifIndex ---> to vlanId) and from that we will get the name
 */
/*
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
*/

func isLinkLocal(ipAddr string) bool {
	ip, _, err := net.ParseCIDR(ipAddr)
	if err != nil {
		ip = net.ParseIP(ipAddr)
	}
	return ip.IsLinkLocalUnicast() && (ip.To4() == nil)
}

func (svr *NDPServer) IsIPv6Addr(ipAddr string) bool {
	ip, _, _ := net.ParseCIDR(ipAddr)
	if ip.To4() == nil {
		return true
	}

	return false
}

/*
func (svr *NDPServer) DeleteNDPEntryFromState(delifIndex int32) {
	for _, ifIndex := range svr.ndpUpIntfStateSlice {
		if delifIndex == ifIndex {
			//svr.ndpUp = append(svr.lldpUpIntfStateSlice[:idx],
			//	svr.lldpUpIntfStateSlice[idx+1:]...)
			break
		}
	}
}
*/

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

		//@TODO: need to remove ndp l3 interface from up slice
	}
	svr.L3Port[ipInfo.IfIndex] = ipInfo
}

func (svr *NDPServer) findL3Port(ifIndex int32) (Interface, bool) {
	l3port, exists := svr.L3Port[ifIndex]
	return l3port, exists
}

/*  API: will handle l2/physical notifications received from switch/asicd
 *	  Update map entry and then call state notification
 *
 */
func (svr *NDPServer) HandlePhyPortStateNotification(msg *config.PortState) {
	debug.Logger.Info("Received State:", msg.IfState, "for ifIndex:", msg.IfIndex)
	l3Port, exists := svr.findL3Port(msg.IfIndex)
	if !exists {
		debug.Logger.Debug("Physical Port for ifIndex:", msg.IfIndex,
			"is not l3 port and ignoring port state notification")
		return
	}
	// search this ifIndex in l3 map to get the ifIndex -> ipAddr map
	switch msg.IfState {
	case config.STATE_UP:
		// if the port state is up, then we need to start RX/TX only for global scope ip address,
		// if it is not started
		debug.Logger.Info("Create pkt handler for", msg.IfIndex, "GS:", l3Port.IpAddr, "LS:", l3Port.LinkLocalIp)
		svr.StartRxTx(msg.IfIndex)

	case config.STATE_DOWN:
		// if the port state is down, then we need to delete all the neighbors for that ifIndex...which
		// includes deleting neighbor from link local ip address also
		debug.Logger.Info("Stop receiving frames for", l3Port.IntfRef)
		svr.StopRxTx(msg.IfIndex, "ALL")
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
	debug.Logger.Info("Received State:", msg.Operation, "for port:", msg.IntfRef, "ifIndex:", msg.IfIndex, "ipAddr:", msg.IpAddr)
	switch msg.Operation {
	case config.STATE_UP:
		debug.Logger.Info("Create pkt handler for port:", msg.IntfRef, "ifIndex:", msg.IfIndex, "IpAddr:", msg.IpAddr)
		svr.StartRxTx(msg.IfIndex)
	case config.STATE_DOWN:
		debug.Logger.Info("Delete pkt handler for port:", msg.IntfRef, "ifIndex:", msg.IfIndex, "IpAddr:", msg.IpAddr)
		// stop pcap handler
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
func (svr *NDPServer) PopulateVlanInfo(nbrInfo *config.NeighborConfig, ifIndex int32) {
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

/*
 * helper function to create notification msg
 */
func createNotificationMsg(ipAddr string, ifIndex int32) ([]byte, error) {
	msg := commonDefs.Ipv6NeighborNotification{
		IpAddr:  ipAddr,
		IfIndex: ifIndex,
	}
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		debug.Logger.Err("Failed to marshal IPv6 Neighbor Notification message", msg, "error:", err)
		return msgBuf, err
	}

	return msgBuf, nil
}

/*
 * helper function to marshal notification and push it on to the channel
 */
func (svr *NDPServer) pushNotification(notification commonDefs.NdpNotification) {
	notifyBuf, err := json.Marshal(notification)
	if err != nil {
		debug.Logger.Err("Failed to marshal ipv6 notification before pushing it on channel error:", err)
		return
	}
	svr.notifyChan <- notifyBuf
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
