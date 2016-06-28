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
	"fmt"
	nanomsg "github.com/op/go-nanomsg"
	"l3/ndp/config"
	"l3/ndp/debug"
)

func NewSwitchPlugin(client *asicdServices.ASICDServicesClient, subSock *nanomsg.SubSocket) {

}

// @TODO: Need to move this to asicdclient mgr... the library is still missing pieces
func getPortsStates(p *AsicPlugin) []*config.PortInfo {
	debug.Logger.Info("Get Port State List")
	currMarker := int64(asicdCommonDefs.MIN_SYS_PORTS)
	more := false
	objCount := 0
	count := 10
	portStates := make([]*config.PortInfo, 0)
	for {
		bulkInfo, err := p.asicdClient.GetBulkPortState(
			asicdServices.Int(currMarker), asicdServices.Int(count))
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

//@TODO: because the FSDaemon is not modular ndp is using arguments for start
func Start(client *asicdServices.ASICDServicesClient, subSock *nanomsg.SubSocket) []*config.PortInfo {
	asicPlugin := &AsicPlugin{client, subSock}
	return getPortsStates(asicPlugin)
}
