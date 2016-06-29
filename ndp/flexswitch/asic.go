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
	"encoding/json"
	"fmt"
	"l3/ndp/debug"
	"sync"
	"utils/commonDefs"
)

var switchInst *commonDefs.AsicdClientStruct = nil
var once sync.Once

func initAsicdNotification() commonDefs.AsicdNotification {
	nMap := make(commonDefs.AsicdNotification)
	nMap = commonDefs.AsicdNotification{
		commonDefs.NOTIFY_L2INTF_STATE_CHANGE:       true,
		commonDefs.NOTIFY_L3INTF_STATE_CHANGE:       true,
		commonDefs.NOTIFY_VLAN_CREATE:               true,
		commonDefs.NOTIFY_VLAN_DELETE:               true,
		commonDefs.NOTIFY_VLAN_UPDATE:               true,
		commonDefs.NOTIFY_LOGICAL_INTF_CREATE:       false,
		commonDefs.NOTIFY_LOGICAL_INTF_DELETE:       false,
		commonDefs.NOTIFY_LOGICAL_INTF_UPDATE:       true,
		commonDefs.NOTIFY_IPV4INTF_CREATE:           true,
		commonDefs.NOTIFY_IPV4INTF_DELETE:           true,
		commonDefs.NOTIFY_LAG_CREATE:                true,
		commonDefs.NOTIFY_LAG_DELETE:                true,
		commonDefs.NOTIFY_LAG_UPDATE:                true,
		commonDefs.NOTIFY_IPV4NBR_MAC_MOVE:          true,
		commonDefs.NOTIFY_IPV4_ROUTE_CREATE_FAILURE: false,
		commonDefs.NOTIFY_IPV4_ROUTE_DELETE_FAILURE: false,
	}
	return nMap
}

func GetSwitchInst() *commonDefs.AsicdClientStruct {
	once.Do(func() {
		notifyMap := initAsicdNotification()
		notifyHdl := &AsicNotificationHdl{}
		notifyHdl.AsicdSubSocketCh = make(chan commonDefs.AsicdNotifyMsg)
		switchInst = &commonDefs.AsicdClientStruct{
			NHdl: notifyHdl,
			NMap: notifyMap,
		}
	})
	return switchInst
}

func (notifyHdl *AsicNotificationHdl) ProcessNotification(msg commonDefs.AsicdNotifyMsg) {
	notifyHdl.AsicdSubSocketCh <- msg
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
