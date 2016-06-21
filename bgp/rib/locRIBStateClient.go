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

// locRIBStateClient.go
package rib

import (
	"bgpd"
	"errors"
	"fmt"
	"models/objects"
)

const (
	LocRIBStateAdd uint8 = iota
	LocRIBStateUpdate
	LocRIBStateDelete
)

var LocRIBStateOperation = map[uint8]string{
	LocRIBStateAdd:    "add",
	LocRIBStateUpdate: "update",
	LocRIBStateDelete: "delete",
}

type RouteInfo struct {
	operation uint8
	route     *bgpd.BGPRouteState
}

func (adjRib *AdjRib) addLocRIBRouteStateToDB(route *bgpd.BGPRouteState) error {
	adjRib.logger.Info(fmt.Sprintf("addLocRIBRouteStateToDB route %s/%d", route.Network, route.CIDRLen))
	var dbObj objects.BGPRouteState
	objects.ConvertThriftTobgpdBGPRouteStateObj(route, &dbObj)
	err := adjRib.dbUtil.StoreObjectInDb(&dbObj)
	if err != nil {
		adjRib.logger.Err(fmt.Sprintf("Failed to add BGP Route %s/%d to DB with error", route.Network,
			route.CIDRLen, err))
		return errors.New(fmt.Sprintf("Failed to add BGP Route %s/%d to DB with error", route.Network,
			route.CIDRLen, err))
	}
	adjRib.logger.Info(fmt.Sprintf("Added route %s/%d to DB", route.Network, route.CIDRLen))
	return nil
}

func (adjRib *AdjRib) delLocRIBRouteStateToDB(route *bgpd.BGPRouteState) error {
	adjRib.logger.Info(fmt.Sprintf("delLocRIBRouteStateToDB route %s/%d", route.Network, route.CIDRLen))
	var dbObj objects.BGPRouteState
	objects.ConvertThriftTobgpdBGPRouteStateObj(route, &dbObj)
	err := adjRib.dbUtil.DeleteObjectFromDb(&dbObj)
	if err != nil {
		adjRib.logger.Err(fmt.Sprintf("Failed to delete BGP Route %s/%d from DB with error", route.Network,
			route.CIDRLen, err))
		return errors.New(fmt.Sprintf("Failed to delete BGP Route %s/%d from DB with error", route.Network,
			route.CIDRLen, err))
	}
	adjRib.logger.Info(fmt.Sprintf("Deleted route %s/%d from DB", route.Network, route.CIDRLen))
	return nil
}

func (adjRib *AdjRib) StartLocRIBRouteReceiver() {
	adjRib.logger.Info("Starting the LocRIB route state receiver")
	var err error

	for {
		err = nil
		select {
		case info := <-adjRib.routeStateCh:
			if info.operation == LocRIBStateAdd {
				err = adjRib.addLocRIBRouteStateToDB(info.route)
			} else if info.operation == LocRIBStateDelete {
				err = adjRib.delLocRIBRouteStateToDB(info.route)
			} else if info.operation == LocRIBStateUpdate {
				//err = adjRib.updLocRIBRouteStateToDB(info.route)
				err = adjRib.delLocRIBRouteStateToDB(info.route)
				if err == nil {
					err = adjRib.addLocRIBRouteStateToDB(info.route)
				}
			} else {
				adjRib.logger.Err(fmt.Sprintf("Recieved unknown route state change operation %d", info.operation))
			}

			if err != nil {
				adjRib.logger.Err(fmt.Sprintf("Failed to %s route state %s/%d", LocRIBStateOperation[info.operation],
					info.route.Network, info.route.CIDRLen))
			}
		}
	}
}
