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
	"fmt"
)

func addAsicdRoute(routeInfoRecord RouteInfoRecord) {
	logger.Info(fmt.Sprintln("addAsicdRoute, weight = ", routeInfoRecord.weight+1, " ipType:", routeInfoRecord.ipType))
	if routeInfoRecord.ipType == ipv4 {
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
	} else if routeInfoRecord.ipType == ipv6 {
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
	logger.Info(fmt.Sprintln("delAsicdRoute with ipType ", routeInfoRecord.ipType))
	if routeInfoRecord.ipType == ipv4 {
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
	} else if routeInfoRecord.ipType == ipv6 {

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
	for {
		select {
		case route := <-ribdServiceHandler.AsicdRouteCh:
			logger.Debug(fmt.Sprintln(" received message on AsicdRouteCh, op:", route.Op, " ip type:", route.OrigConfigObject.(RouteInfoRecord).ipType))
			if route.Op == "add" {
				addAsicdRoute(route.OrigConfigObject.(RouteInfoRecord))
			} else if route.Op == "del" {
				delAsicdRoute(route.OrigConfigObject.(RouteInfoRecord))
			}
		}
	}
}
