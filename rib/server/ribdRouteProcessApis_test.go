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
	"asicd/asicdCommonDefs"
	"encoding/json"
	"fmt"
	"ribd"
	"ribdInt"
	"strconv"
	"testing"
	"time"
)

type testIpInfo struct {
	ipAddr string
	mask   string
}

var server *RIBDServer
var ipAddrList []testIpInfo
var ipRouteList []*ribd.IPv4Route
var patchOpList []*ribd.PatchOpInfo
var logicalIntfList []asicdCommonDefs.LogicalIntfNotifyMsg

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
func InitLogicalIntfList() {
	logicalIntfList = make([]asicdCommonDefs.LogicalIntfNotifyMsg, 0)
	logicalIntfList = append(logicalIntfList, asicdCommonDefs.LogicalIntfNotifyMsg{
		IfIndex:         1,
		LogicalIntfName: "lo1",
	})
	logicalIntfList = append(logicalIntfList, asicdCommonDefs.LogicalIntfNotifyMsg{
		IfIndex:         2,
		LogicalIntfName: "lo2",
	})
	logicalIntfList = append(logicalIntfList, asicdCommonDefs.LogicalIntfNotifyMsg{
		IfIndex:         3,
		LogicalIntfName: "lo3",
	})
	logicalIntfList = append(logicalIntfList, asicdCommonDefs.LogicalIntfNotifyMsg{
		IfIndex:         4,
		LogicalIntfName: "lo4",
	})
	logicalIntfList = append(logicalIntfList, asicdCommonDefs.LogicalIntfNotifyMsg{
		IfIndex:         5,
		LogicalIntfName: "lo5",
	})
}
func InitIpInfoList() {
	ipAddrList = make([]testIpInfo, 0)
	ipAddrList = append(ipAddrList, testIpInfo{"11.1.10.2", "255.255.255.0"})
	ipAddrList = append(ipAddrList, testIpInfo{"12.1.10.2", "255.255.255.0"})
	ipAddrList = append(ipAddrList, testIpInfo{"12.1.10.20", "255.255.255.0"})
	ipAddrList = append(ipAddrList, testIpInfo{"13.1.10.2", "255.255.255.0"})
	ipAddrList = append(ipAddrList, testIpInfo{"22.1.10.2", "255.255.255.0"})
	ipAddrList = append(ipAddrList, testIpInfo{"33.1.10.2", "255.255.255.0"})
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
		DestinationNw: "60.1.10.0",
		NetworkMask:   "255.255.255.0",
		NextHop:       []*ribd.NextHopInfo{&ribd.NextHopInfo{NextHopIp: "12.1.10.20", NextHopIntRef: "lo2"}},
		Protocol:      "STATIC",
		Cost:          20,
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
	InitLogicalIntfList()
	InitIpInfoList()
	InitRouteList()
	InitPatchOpList()
	fmt.Println("****************")
}
func TestProcessLogicalIntfCreateEvent(t *testing.T) {
	fmt.Println("**** Test LogicalIntfCreate event ****")
	for _, lo := range logicalIntfList {
		server.ProcessLogicalIntfCreateEvent(lo)
	}
	fmt.Println("***************************************")
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
func TestResolveNextHop(t *testing.T) {
	fmt.Println("****TestResolveNextHop****")
	for _, ipAddr := range ipAddrList {
		nh, rnh, err := ResolveNextHop(ipAddr.ipAddr)
		fmt.Println("nh:", nh, " rnh:", rnh, " err:", err, " for ipAddr:", ipAddr.ipAddr)
	}
	fmt.Println("****************************")
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
	TestResolveNextHop(t)
	TestGetRoute(t)
	fmt.Println("************************************")
}
func TestScaleRouteCreate(t *testing.T) {
	fmt.Println("****TestScaleRouteCreate****")
	timeFmt := "2006-01-02 15:04:05.999999999 -0700 PDT"
	var count int = 0
	var maxCount int = 30000
	intByt2 := 1
	intByt3 := 1
	byte1 := "22"
	byte4 := "0"
	var routes []*ribdInt.IPv4RouteConfig
	var route []ribdInt.IPv4RouteConfig
	var scaleTestStartTime string
	var scaleTestEndTime string
	var err error
	var startTime time.Time
	var endTime time.Time
	routeCount, _ := server.GetTotalRouteCount()
	fmt.Println("Route count before scale test start:", routeCount)
	routes = make([]*ribdInt.IPv4RouteConfig, 0)
	route = make([]ribdInt.IPv4RouteConfig, maxCount)
	for {
		if intByt3 > 254 {
			intByt3 = 1
			intByt2++
		} else {
			intByt3++
		}
		if intByt2 > 254 {
			intByt2 = 1
		} //else {
		//intByt2++
		//}

		byte2 := strconv.Itoa(intByt2)
		byte3 := strconv.Itoa(intByt3)
		rtNet := byte1 + "." + byte2 + "." + byte3 + "." + byte4
		route[count].DestinationNw = rtNet
		route[count].NetworkMask = "255.255.255.0"
		route[count].NextHop = make([]*ribdInt.RouteNextHopInfo, 0)
		nh := ribdInt.RouteNextHopInfo{
			NextHopIp: "11.1.10.2",
		}
		route[count].NextHop = append(route[count].NextHop, &nh)
		route[count].Protocol = "STATIC"
		routes = append(routes, &route[count])
		count++
		if maxCount == count {
			fmt.Println("Done. Total route configs added ", count)
			break
		}
		//fmt.Println("Creating Route ", route)
		/*		_, err := server.ProcessRouteCreateConfig(&route)
				if err == nil {
					if count == 0 {
						fmt.Println("recording starttime as ", routeCreatedTime)
						scaleTestStartTime = routeCreatedTime
					}
					count++
				} else {
					fmt.Println("Call failed", err, "count: ", count)
					return
				}
				if maxCount == count {
					fmt.Println("Done. Total calls executed", count)
					fmt.Println("recording endtime as ", routeCreatedTime)
					scaleTestEndTime = routeCreatedTime
					break
				}*/
	}
	/*	fmt.Println("startTime:", scaleTestStartTime)
		startTime, err := time.Parse(timeFmt, scaleTestStartTime)
		if err != nil {
			fmt.Println("err parsing obj time:", scaleTestStartTime, " into timeFmt:", timeFmt, " err:", err)
			return
		}
		fmt.Println("endTime:", scaleTestEndTime)
		endTime, err := time.Parse(timeFmt, scaleTestEndTime)
		if err != nil {
			fmt.Println("err parsing obj time:", scaleTestEndTime, " into timeFmt:", timeFmt, " err:", err)
			return
		}
		fmt.Println("Time to install ", maxCount, " number of routes is:", "duration:", endTime.Sub(startTime))
	*/
	server.ProcessBulkRouteCreateConfig(routes)
	scaleTestStartTime, err = server.GetRouteCreatedTime(routeCount + 1)
	if err != nil {
		fmt.Println("err ", err, " getting routecreated time for route #", routeCount+1)
		return
	}
	fmt.Println("startTime:", scaleTestStartTime, " for the ", routeCount+1, " route")
	startTime, err = time.Parse(timeFmt, scaleTestStartTime)
	if err != nil {
		fmt.Println("err parsing obj time:", scaleTestStartTime, " into timeFmt:", timeFmt, " err:", err)
		return
	}
	scaleTestEndTime, err = server.GetRouteCreatedTime(routeCount + maxCount)
	if err != nil {
		fmt.Println("err ", err, " getting routecreated time for route #", routeCount+maxCount)
		for {
			scaleTestEndTime, err = server.GetRouteCreatedTime(routeCount + maxCount)
			if err == nil {
				break
			}
		}
		//return
	}
	fmt.Println("endTime:", scaleTestEndTime, " after the ", routeCount+maxCount, " route")
	endTime, err = time.Parse(timeFmt, scaleTestEndTime)
	if err != nil {
		fmt.Println("err parsing obj time:", scaleTestEndTime, " into timeFmt:", timeFmt, " err:", err)
		return
	}
	fmt.Println("GetRouteCreatedTime() method Time to install ", maxCount, " number of routes is:", "duration:", endTime.Sub(startTime))

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
	TestResolveNextHop(t)
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
	TestResolveNextHop(t)
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
	TestResolveNextHop(t)
	fmt.Println("************************************")
}
