//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//       Unless required by applicable law or agreed to in writing, software
//       distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//       See the License for the specific language governing permissions and
//       limitations under the License.
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
	"fmt"
	"ribd"
	"testing"
)

type testIpInfo struct {
	ipAddr string
	mask   string
}

var server *RIBDServer
var ipAddrList []testIpInfo
var ipRouteList []*ribd.IPv4Route
var patchOpList []*ribd.PatchOpInfo

func InitTestServer() {
	fmt.Println("Init server ")
	routeServer = getServerObject()
	if routeServer == nil {
		logger.Println("routeServer nil")
		return
	}
	server = routeServer
	go server.StartServer("/opt/flexswitch/params/")
	fmt.Println("route server started")
}
func InitIpInfoList() {
	ipAddrList = make([]testIpInfo, 0)
	ipAddrList = append(ipAddrList, testIpInfo{"40.0.1.2", "255.255.255.0"})
	ipAddrList = append(ipAddrList, testIpInfo{"40.1.10.2", "255.255.255.0"})
	ipAddrList = append(ipAddrList, testIpInfo{"50.1.10.2", "255.255.255.0"})

}
func InitPatchOpList() {
	patchOpList = make([]*ribd.PatchOpInfo, 0)
	nhbytes, _ := json.Marshal([]*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "13.1.10.2", NextHopIntRef: "lo3"}})
	patchOpList = append(patchOpList, &ribd.PatchOpInfo{
		Op:    "add",
		Path:  "NextHop",
		Value: string(nhbytes),
	})
	costbytes, _ := json.Marshal(10)
	patchOpList = append(patchOpList, &ribd.PatchOpInfo{
		Op:    "add",
		Path:  "Cost",
		Value: string(costbytes),
	})
	patchOpList = append(patchOpList, &ribd.PatchOpInfo{
		Op:    "remove",
		Path:  "NextHop",
		Value: string(nhbytes),
	})
	nhbytes1, _ := json.Marshal([]*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "14.1.10.2", NextHopIntRef: "lo4"}})
	patchOpList = append(patchOpList, &ribd.PatchOpInfo{
		Op:    "remove",
		Path:  "NextHop",
		Value: string(nhbytes1),
	})
	patchOpList = append(patchOpList, &ribd.PatchOpInfo{
		Op:    "remove",
		Path:  "Cost",
		Value: string(costbytes),
	})
	patchOpList = append(patchOpList, &ribd.PatchOpInfo{
		Op:    "test",
		Path:  "Cost",
		Value: string(costbytes),
	})
}
func InitRouteList() {
	ipRouteList = make([]*ribd.IPv4Route, 0)
	ipRouteList = append(ipRouteList, &ribd.IPv4Route{
		DestinationNw: "40.1.10.0",
		NetworkMask:   "255.255.255.0",
		NextHop:       []*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "11.1.10.2", NextHopIntRef: "lo1"}},
		Protocol:      "EBGP",
	})
	ipRouteList = append(ipRouteList, &ribd.IPv4Route{
		DestinationNw: "50.1.10.0",
		NetworkMask:   "255.255.255.0",
		NextHop:       []*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "12.1.10.20", NextHopIntRef: "lo2"}},
		Protocol:      "STATIC",
	})
	ipRouteList = append(ipRouteList, &ribd.IPv4Route{
		DestinationNw: "40.1.10.0",
		NetworkMask:   "255.255.255.0",
		NextHop:       []*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "22.1.10.2", NextHopIntRef: "22"}},
		Protocol:      "CONNECTED",
	})
	ipRouteList = append(ipRouteList, &ribd.IPv4Route{
		DestinationNw: "40.1.10.0",
		NetworkMask:   "255.255.255.0",
		NextHop:       []*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "33.1.10.2", NextHopIntRef: "33"}},
		Protocol:      "STATIC",
	})
}
func TestInitServer(t *testing.T) {
	fmt.Println("Test InitServer")
	InitTestServer()
	InitIpInfoList()
	InitRouteList()
	InitPatchOpList()
	fmt.Println("****************")
}
func TestGetRouteReachability(t *testing.T) {
	fmt.Println("**** Test GetRouteReachability****")
	for _, ipAddr := range ipAddrList {
		fmt.Println("check route reachability of ipAddr:", ipAddr.ipAddr)
		nh, err := server.GetRouteReachabilityInfo(ipAddr.ipAddr)
		if err != nil {
			fmt.Println("error ", err, " getting route reachability for ip:", ipAddr)
			continue
		}
		fmt.Println("nh:", nh)
	}
	fmt.Println("*************************************")
}
func TestGetRoute(t *testing.T) {
	fmt.Println("**** TestGetRoute****")
	for _, ipInfo := range ipAddrList {
		rt, err := server.GetRoute(ipInfo.ipAddr, ipInfo.mask)
		if err != nil {
			fmt.Println("error getting ip info for ip:", ipInfo.ipAddr, ":", ipInfo.mask)
			continue
		}
		fmt.Println("rt info:", rt)
	}
	fmt.Println("**********************")
}
func TestProcessRouteCreateConfig(t *testing.T) {
	fmt.Println("****TestProcessRouteCreateConfig****")
	for _, v4route := range ipRouteList {
		val, err := server.ProcessRouteCreateConfig(v4route)
		fmt.Println("val = ", val, " err: ", err, " for route:", v4route)
	}
	val, err := server.ProcessRouteCreateConfig(ipRouteList[0])
	fmt.Println("val = ", val, " err: ", err, " for route:", ipRouteList[0])
	TestGetRouteReachability(t)
	TestGetRoute(t)
	fmt.Println("************************************")
}
func TestProcessRouteUpdateConfig(t *testing.T) {
	fmt.Println("****TestProcessRouteUpdateConfig****")
	for _, v4Route := range ipRouteList {
		var newRoute ribd.IPv4Route
		newRoute = *v4Route
		newRoute.Cost = 80
		newRoute.NextHop = []*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "12.1.10.20", Weight: 20}}
		attrSet := make([]bool, 6) //number of fields in ribd.IPv4Route
		attrSet[3] = true          //set cost attr to true
		attrSet[4] = true          //NUll route attr to true
		attrSet[5] = true          //set next hop ip attr to true
		val, err := server.ProcessRouteUpdateConfig(v4Route, &newRoute, attrSet)
		fmt.Println("val = ", val, " err: ", err)
	}
	TestGetRouteReachability(t)
	TestGetRoute(t)
	fmt.Println("************************************")
}
func TestProcessRoutePatchUpdateConfig(t *testing.T) {
	fmt.Println("****TestProcessRoutePatchUpdateConfig****")
	for _, v4Route := range ipRouteList {
		for _, op := range patchOpList {
			fmt.Println("Applying patch:", op, " to route:", v4Route)
			testRoute := *v4Route
			val, err := server.ProcessRoutePatchUpdateConfig(&testRoute, &testRoute, []*ribd.PatchOpInfo{op})
			fmt.Println("val = ", val, " err: ", err, " for testRoute:", testRoute)
			TestGetRoute(t)
		}
	}
	TestGetRouteReachability(t)
	TestGetRoute(t)
	fmt.Println("************************************")
}
func TestProcessRouteDeleteConfig(t *testing.T) {
	fmt.Println("****TestProcessRouteDeleteConfig****")
	for _, v4Route := range ipRouteList {
		val, err := server.ProcessRouteDeleteConfig(v4Route)
		fmt.Println("val = ", val, " err: ", err)
	}
	TestGetRouteReachability(t)
	TestGetRoute(t)
	fmt.Println("************************************")
}
