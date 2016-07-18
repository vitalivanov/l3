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
	"fmt"
	"testing"
)

var logicalIntfList []asicdCommonDefs.LogicalIntfNotifyMsg
var vlanList []asicdCommonDefs.VlanNotifyMsg
var ipv4IntfList []asicdCommonDefs.IPv4IntfNotifyMsg
var logicalIntfListInit, ipv4IntfListInit bool

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
func InitVlanList() {
	vlanList = make([]asicdCommonDefs.VlanNotifyMsg, 0)
	vlanList = append(vlanList, asicdCommonDefs.VlanNotifyMsg{
		VlanId:   100,
		VlanName: "vlan100",
	})
	vlanList = append(vlanList, asicdCommonDefs.VlanNotifyMsg{
		VlanId:   200,
		VlanName: "vlan200",
	})
}
func InitIPv4IntfList() {
	ipv4IntfList = make([]asicdCommonDefs.IPv4IntfNotifyMsg, 0)
	ipv4IntfList = append(ipv4IntfList, asicdCommonDefs.IPv4IntfNotifyMsg{
		IpAddr:  "11.1.10.2/24",
		IfIndex: 1,
	})
	ipv4IntfList = append(ipv4IntfList, asicdCommonDefs.IPv4IntfNotifyMsg{
		IpAddr:  "21.1.10.2/24",
		IfIndex: 2,
	})
	ipv4IntfList = append(ipv4IntfList, asicdCommonDefs.IPv4IntfNotifyMsg{
		IpAddr:  "31.1.10.2/24",
		IfIndex: 3,
	})
	ipv4IntfList = append(ipv4IntfList, asicdCommonDefs.IPv4IntfNotifyMsg{
		IpAddr:  "35.1.10.2/24",
		IfIndex: 35,
	})
}
func TestInitRtEventHdlrTestServer(t *testing.T) {
	fmt.Println("****Init Route event handler Server****")
	StartTestServer()
	InitLogicalIntfList()
	InitVlanList()
	InitIPv4IntfList()
	fmt.Println("****************")
}
func TestProcessLogicalIntfCreateEvent(t *testing.T) {
	fmt.Println("**** Test LogicalIntfCreate event ****")
	if logicalIntfListInit == true {
		fmt.Println("List already initialized")
		return
	}
	fmt.Println("IntfIdNameMap before:")
	fmt.Println(IntfIdNameMap)
	fmt.Println("IfNameToIfIndex before:")
	fmt.Println(IfNameToIfIndex)
	for _, lo := range logicalIntfList {
		server.ProcessLogicalIntfCreateEvent(lo)
	}
	fmt.Println("IntfIdNameMap after:")
	fmt.Println(IntfIdNameMap)
	fmt.Println("IfNameToIfIndex after:")
	fmt.Println(IfNameToIfIndex)
	logicalIntfListInit = true
	fmt.Println("***************************************")
}
func TestVlanCreateEvent(t *testing.T) {
	fmt.Println("**** TestVlanCreateEvent event ****")
	fmt.Println("IntfIdNameMap before:")
	fmt.Println(IntfIdNameMap)
	fmt.Println("IfNameToIfIndex before:")
	fmt.Println(IfNameToIfIndex)
	for _, vlan := range vlanList {
		server.ProcessVlanCreateEvent(vlan)
	}
	fmt.Println("IntfIdNameMap after:")
	fmt.Println(IntfIdNameMap)
	fmt.Println("IfNameToIfIndex after:")
	fmt.Println(IfNameToIfIndex)
	fmt.Println("***************************************")
}
func TestIPv4IntfCreateEvent(t *testing.T) {
	fmt.Println("**** TestIPv4IntfCreateEvent event ****")
	if ipv4IntfListInit == true {
		fmt.Println("List already initialized")
		return
	}
	for _, v4Intf := range ipv4IntfList {
		server.ProcessIPv4IntfCreateEvent(v4Intf)
	}
	ipv4IntfListInit = true
	fmt.Println("***************************************")
}
func TestProcessL3IntfStateChangeEvents(t *testing.T) {
	fmt.Println("****TestProcessL3IntfStateChangeEvents()****")
	TestGetRouteReachability(t)
	for _, ipInfo := range ipAddrList {
		server.ProcessL3IntfDownEvent(ipInfo.ipAddr)
	}
	TestGetRouteReachability(t)
	for _, ipInfo := range ipAddrList {
		server.ProcessL3IntfUpEvent(ipInfo.ipAddr)
	}
	TestGetRouteReachability(t)
	fmt.Println("********************************************")
}
func TestIPv4IntfDeleteEvent(t *testing.T) {
	fmt.Println("**** TestIPv4IntfDeleteEvent event ****")
	v4Intf := asicdCommonDefs.IPv4IntfNotifyMsg{
		IpAddr:  "31.1.10.2/24",
		IfIndex: 3,
	}
	server.ProcessIPv4IntfDeleteEvent(v4Intf)
	v4Intf = asicdCommonDefs.IPv4IntfNotifyMsg{
		IpAddr:  "61.1.10.2/24",
		IfIndex: 6,
	}
	server.ProcessIPv4IntfDeleteEvent(v4Intf)
	fmt.Println("***************************************")
}
