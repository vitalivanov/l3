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

// test_route_ops
package routeThriftTest

import (
	"fmt"
	"ribd"
)

var route ribd.IPv4Route
var ipv4RouteList []ribd.IPv4Route
var reachabilityTestList []string

func Createv4Routes(client *ribd.RIBDServicesClient) {
	fmt.Println("CreateRoutes")
	for _, route := range ipv4RouteList {
		client.CreateIPv4Route(&route)
	}
}
func Deletev4Routes(client *ribd.RIBDServicesClient) {
	fmt.Println("DeleteRoutes")
	for _, route := range ipv4RouteList {
		client.DeleteIPv4Route(&route)
	}
}
func CheckRouteReachability(client *ribd.RIBDServicesClient) {
	fmt.Println("CheckRouteReachability")
	for _, dest := range reachabilityTestList {
		nhIntf, err := client.GetRouteReachabilityInfo(dest)
		fmt.Println("nhIntf info for ", dest, ":", nhIntf, " err:", err)
	}
}
func Createv4RouteList() {
	ipv4RouteList = make([]ribd.IPv4Route,0)
	ipv4RouteList = append(ipv4RouteList,ribd.IPv4Route{
		DestinationNw: "40.1.10.0",
		NetworkMask:   "255.255.255.0",
		NextHop:       []*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "40.1.1.2", NextHopIntRef: "lo1"}},
		Protocol:      "STATIC",
	})

	//reachability test list
	reachabilityTestList = make([]string,0)
	reachabilityTestList = append(reachabilityTestList,"40.0.1.2")
	reachabilityTestList = append(reachabilityTestList,"40.1.1.2")
	reachabilityTestList = append(reachabilityTestList,"40.1.10.2")
}
