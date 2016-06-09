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

// ribdRouteServer.go
package server

import (
	"ribd"
	"fmt"
)

func (ribdServiceHandler *RIBDServer) StartRouteProcessServer() {
	logger.Info("Starting the routeserver loop")
	for {
		select {
		case routeConf := <-ribdServiceHandler.RouteConfCh:
			logger.Debug(fmt.Sprintln("received message on RouteConfCh channel, op: ", routeConf.Op))
			if routeConf.Op == "add" {
			    ribdServiceHandler.ProcessRouteCreateConfig(routeConf.OrigConfigObject.(*ribd.IPv4Route))
			} else if routeConf.Op == "del" {
				ribdServiceHandler.ProcessRouteDeleteConfig(routeConf.OrigConfigObject.(*ribd.IPv4Route))
			} else if routeConf.Op == "update" {
				if routeConf.PatchOp == nil || len(routeConf.PatchOp) == 0 {
                      ribdServiceHandler.ProcessRouteUpdateConfig(routeConf.OrigConfigObject.(*ribd.IPv4Route), routeConf.NewConfigObject.(*ribd.IPv4Route), routeConf.AttrSet)
				} else {
                     ribdServiceHandler.ProcessRoutePatchUpdateConfig(routeConf.OrigConfigObject.(*ribd.IPv4Route), routeConf.NewConfigObject.(*ribd.IPv4Route), routeConf.PatchOp)
				}
			} else if routeConf.Op == "addv6" {
				//create ipv6 route
			} else if routeConf.Op == "delv6" {
				//delete ipv6 route
			} else if routeConf.Op == "updatev6" {
				//update ipv6 route
				if routeConf.PatchOp == nil || len(routeConf.PatchOp) == 0 {
			    } else {
				//patch update
			    }
			}
		}
	}
}
