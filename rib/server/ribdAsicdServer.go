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

// ribdAsicdServer.go
package server

import (
	"asicdInt"
	//"fmt"
	"l3/rib/ribdCommonDefs"
)

var asicdBulkCount = 30000
var asicdv4RouteCount = 0
var asicdv4Routes []*asicdInt.IPv4Route
var asicdv4Route []asicdInt.IPv4Route
var asicdv6Route []asicdInt.IPv6Route

func addAsicdRouteBulk(routeInfoRecord RouteInfoRecord, bulkEnd bool) {
	logger.Info("addAsicdRouteBulk, bulkEnd:", bulkEnd)
	if asicdclnt.IsConnected == false {
		return
	}
	ipType := ""
	if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
		ipType = "IPv4"
	} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
		ipType = "IPv6"
	}
	logger.Info("addAsicdRoute, weight = ", routeInfoRecord.weight+1, " ipType:", ipType)
	if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
		if asicdv4RouteCount == 0 {
			asicdv4Routes = make([]*asicdInt.IPv4Route, 0)
		}
		asicdv4Routes = append(asicdv4Routes,
			&asicdInt.IPv4Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv4NextHop{
					&asicdInt.IPv4NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
					},
				},
			})
		asicdv4RouteCount++
		if asicdv4RouteCount == asicdBulkCount || bulkEnd {
			asicdclnt.ClientHdl.OnewayCreateIPv4Route(asicdv4Routes)
			asicdv4Routes = nil
			asicdv4RouteCount = 0
		}
	} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
	}
}
func addAsicdRoute(routeInfoRecord RouteInfoRecord) {
	if asicdclnt.IsConnected == false {
		return
	}
	/*	ipType := ""
		if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
			ipType = "IPv4"
		} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
			ipType = "IPv6"
		}
		logger.Info("addAsicdRoute, weight = ", routeInfoRecord.weight+1, " ipType:", ipType)*/
	if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
		//logger.Info("ipv4 route, calling onewaycreateipv4 route")
		/*	asicdRoute = make([]asicdInt.IPv4Route, asicdBulkCount)
			if asicdRouteCount == 0 {
				asicdRoutes = make([]*asicdInt.IPv4Route, 0)
			}
			asicdRoute[asicdRouteCount] = asicdInt.IPv4Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv4NextHop{
					&asicdInt.IPv4NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
					},
				},
			}
			asicdRoutes = append(asicdRoutes, &asicdRoute[asicdRouteCount])
			asicdRouteCount++
			if asicdRouteCount == asicdBulkCount {
				asicdclnt.ClientHdl.OnewayCreateIPv4Route(asicdRoutes)
				asicdRoutes = nil
				asicdRouteCount = 0
			}*/
		asicdclnt.ClientHdl.OnewayCreateIPv4Route([]*asicdInt.IPv4Route{
			&asicdInt.IPv4Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv4NextHop{
					&asicdInt.IPv4NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
					},
				},
			},
		})
	} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
		asicdclnt.ClientHdl.OnewayCreateIPv6Route([]*asicdInt.IPv6Route{
			&asicdInt.IPv6Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv6NextHop{
					&asicdInt.IPv6NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
					},
				},
			},
		})
	}
}
func delAsicdRoute(routeInfoRecord RouteInfoRecord) {
	if asicdclnt.IsConnected == false {
		return
	}
	logger.Info("delAsicdRoute with ipType ", routeInfoRecord.ipType)
	if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
		asicdclnt.ClientHdl.OnewayDeleteIPv4Route([]*asicdInt.IPv4Route{
			&asicdInt.IPv4Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv4NextHop{
					&asicdInt.IPv4NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
						//NextHopIfType: int32(routeInfoRecord.resolvedNextHopIpIntf.NextHopIfType),
					},
				},
			},
		})
	} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {

		asicdclnt.ClientHdl.OnewayDeleteIPv6Route([]*asicdInt.IPv6Route{
			&asicdInt.IPv6Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv6NextHop{
					&asicdInt.IPv6NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
						//NextHopIfType: int32(routeInfoRecord.resolvedNextHopIpIntf.NextHopIfType),
					},
				},
			},
		})

	}
}
func (ribdServiceHandler *RIBDServer) StartAsicdServer() {
	logger.Info("Starting the asicdserver loop")
	asicdv4Route = make([]asicdInt.IPv4Route, asicdBulkCount)
	asicdv6Route = make([]asicdInt.IPv6Route, asicdBulkCount)
	for {
		select {
		case route := <-ribdServiceHandler.AsicdRouteCh:
			//logger.Debug(" received message on AsicdRouteCh, op:", route.Op, " ip type:", route.OrigConfigObject.(RouteInfoRecord).ipType, " bulk:", route.Bulk, " bulkEnd:", route.BulkEnd)
			if route.Op == "add" {
				if route.Bulk {
					addAsicdRouteBulk(route.OrigConfigObject.(RouteInfoRecord), route.BulkEnd)
				} else {
					addAsicdRoute(route.OrigConfigObject.(RouteInfoRecord))
				}
			} else if route.Op == "del" {
				delAsicdRoute(route.OrigConfigObject.(RouteInfoRecord))
			}
		}
	}
}
