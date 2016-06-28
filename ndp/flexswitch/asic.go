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
	"asicd/asicdCommonDefs"
	"asicdServices"
	"encoding/json"
	"fmt"
	nanomsg "github.com/op/go-nanomsg"
	"l3/ndp/config"
	"l3/ndp/debug"
)

func NewSwitchPlugin(client *asicdServices.ASICDServicesClient, subSock *nanomsg.SubSocket) {

}

// @TODO: Need to move this to asicdclient mgr... the library is still missing pieces
func (p *AsicPlugin) getPortsStates() []*config.PortInfo {
	debug.Logger.Info("Get Port State List")
	currMarker := int64(asicdCommonDefs.MIN_SYS_PORTS)
	more := false
	objCount := 0
	count := 10
	portStates := make([]*config.PortInfo, 0)
	for {
		bulkInfo, err := p.asicdClient.GetBulkPortState(asicdServices.Int(currMarker), asicdServices.Int(count))
		if err != nil {
			debug.Logger.Err(fmt.Sprintln(": getting bulk port config"+
				" from asicd failed with reason", err))
			//return
			break
		}
		objCount = int(bulkInfo.Count)
		more = bool(bulkInfo.More)
		currMarker = int64(bulkInfo.EndIdx)
		for i := 0; i < objCount; i++ {
			obj := bulkInfo.PortStateList[i]
			port := &config.PortInfo{
				IntfRef:   obj.IntfRef,
				IfIndex:   obj.IfIndex,
				OperState: obj.OperState,
				Name:      obj.Name,
			}
			pObj, err := p.asicdClient.GetPort(obj.Name)
			if err != nil {
				debug.Logger.Err(fmt.Sprintln("Getting mac address for",
					obj.Name, "failed, error:", err))
			} else {
				port.MacAddr = pObj.MacAddr
				port.Description = pObj.Description
			}
			portStates = append(portStates, port)
		}
		if more == false {
			break
		}
	}
	debug.Logger.Info("Done with Port State list")
	return portStates
}

func (p *AsicPlugin) getVlanStates() {
	debug.Logger.Info("Get Vlans")
	objCount := 0
	var currMarker int64
	more := false
	count := 10
	for {
		bulkInfo, err := p.asicdClient.GetBulkVlanState(asicdServices.Int(currMarker), asicdServices.Int(count))
		if err != nil {
			debug.Logger.Err(fmt.Sprintln("getting bulk vlan config",
				"from asicd failed with reason", err))
			return
		}
		objCount = int(bulkInfo.Count)
		more = bool(bulkInfo.More)
		currMarker = int64(bulkInfo.EndIdx)
		for i := 0; i < objCount; i++ {
			//svr.VrrpCreateVlanEntry(int(bulkInfo.VlanStateList[i].VlanId),
			//	bulkInfo.VlanStateList[i].VlanName)
		}
		if more == false {
			break
		}
	}
}

func (p *AsicPlugin) getIPIntf() []*config.IPv6IntfInfo {
	debug.Logger.Info("Get IPv6 Interface List")
	objCount := 0
	var currMarker int64
	more := false
	count := 10
	ipStates := make([]*config.IPv6IntfInfo, 0)
	for {
		bulkInfo, err := p.asicdClient.GetBulkIPv6IntfState(asicdServices.Int(currMarker), asicdServices.Int(count))
		if err != nil {
			debug.Logger.Err(fmt.Sprintln("getting bulk ipv6 intf config",
				"from asicd failed with reason", err))
			return nil
		}
		objCount = int(bulkInfo.Count)
		more = bool(bulkInfo.More)
		currMarker = int64(bulkInfo.EndIdx)
		for i := 0; i < objCount; i++ {
			obj := bulkInfo.IPv6IntfStateList[i]
			ipInfo := &config.IPv6IntfInfo{
				IntfRef:   obj.IntfRef,
				IfIndex:   obj.IfIndex,
				OperState: obj.OperState,
				IpAddr:    obj.IpAddr,
			}
			ipStates = append(ipStates, ipInfo)
		}
		if more == false {
			break
		}
	}
	debug.Logger.Info("Done with IPv6 State list")
	return ipStates
}

//@TODO: because the FSDaemon is not modular ndp is using arguments for start
func GetPorts(client *asicdServices.ASICDServicesClient, subSock *nanomsg.SubSocket) []*config.PortInfo {
	asicPlugin := &AsicPlugin{client, subSock}
	return asicPlugin.getPortsStates()
}

//@TODO: for futuer if NDP needs stub code is already present
func GetVlans(client *asicdServices.ASICDServicesClient, subSock *nanomsg.SubSocket) {
	//asicPlugin := &AsicPlugin{client, subSock}
	return //asicPlugin.getVlanStates()
}

func GetIPIntf(client *asicdServices.ASICDServicesClient, subSock *nanomsg.SubSocket) []*config.IPv6IntfInfo {
	asicPlugin := &AsicPlugin{client, subSock}
	return asicPlugin.getIPIntf()
}

func ProcessMsg(rxBuf []byte) {
	var err error
	var msg asicdCommonDefs.AsicdNotification
	err = json.Unmarshal(rxBuf, &msg)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Unable to Unmarshal asicd msg:", msg.Msg))
		return
	}
	switch msg.MsgType {
	case asicdCommonDefs.NOTIFY_L2INTF_STATE_CHANGE:
		var l2IntfStateNotifyMsg asicdCommonDefs.L2IntfStateNotifyMsg
		err = json.Unmarshal(msg.Msg, &l2IntfStateNotifyMsg)
		if err != nil {
			debug.Logger.Err(fmt.Sprintln("Unable to Unmarshal l2 intf",
				"state change:", msg.Msg))
			break
		}
		if l2IntfStateNotifyMsg.IfState == asicdCommonDefs.INTF_STATE_UP {
			//api.SendPortStateChange(l2IntfStateNotifyMsg.IfIndex, "UP")
		} else {
			//api.SendPortStateChange(l2IntfStateNotifyMsg.IfIndex, "DOWN")
		}
	}
}
