// hw.go
package vxlan

import (
	"arpd"
	hwconst "asicd/asicdConstDefs"
	"asicd/pluginManager/pluginCommon"
	"asicdInt"
	"asicdServices"
	"encoding/json"
	"fmt"
	"git.apache.org/thrift.git/lib/go/thrift"
	"io/ioutil"
	"l3/tunnel/vxlan/vxlan_linux"
	"net"
	"ribd"
	"strconv"
	"strings"
	"time"
	"utils/commonDefs"
	"utils/ipcutils"
)

// vtep vlan membership
var PortVlanDb map[uint16][]*portVlanValue
var PortConfigMap map[int32]portConfig
var softswitch *vxlan_linux.VxlanLinux

type portVlanValue struct {
	ifIndex string
	refCnt  int
}

type portConfig struct {
	Name         string
	HardwareAddr net.HardwareAddr
	Speed        int32
	PortNum      int32
	IfIndex      int32
}

type VXLANClientBase struct {
	Address            string
	Transport          thrift.TTransport
	PtrProtocolFactory *thrift.TBinaryProtocolFactory
	IsConnected        bool
}

type AsicdClient struct {
	VXLANClientBase
	ClientHdl *asicdServices.ASICDServicesClient
}

type RibdClient struct {
	VXLANClientBase
	ClientHdl *ribd.RIBDServicesClient
}

type ArpdClient struct {
	VXLANClientBase
	ClientHdl *arpd.ARPDServicesClient
}

type ClientJson struct {
	Name string `json:Name`
	Port int    `json:Port`
}

var asicdclnt AsicdClient
var ribdclnt RibdClient
var arpdclnt ArpdClient

// variable functions
var hwCreateVxlan = asicDCreateVxlan
var hwDeleteVxlan = asicDDeleteVxlan
var hwCreateVtep = asicDCreateVtep
var hwDeleteVtep = asicDDeleteVtep
var hwGetNextHop = ribDGetNextHopInfo
var hwResolveMac = arpDResolveNextHopMac

func ConvertVxlanConfigToVxlanLinuxConfig(c *VxlanConfig) *vxlan_linux.VxlanConfig {

	return &vxlan_linux.VxlanConfig{
		VNI:    c.VNI,
		VlanId: c.VlanId,
		Group:  c.Group,
		MTU:    c.MTU,
	}
}

func ConvertVxlanConfigToVxlanAsicdConfig(c *VxlanConfig) *asicdInt.Vxlan {

	return &asicdInt.Vxlan{
		Vni:      int32(c.VNI),
		VlanId:   int16(c.VlanId),
		McDestIp: c.Group.String(),
		Mtu:      int32(c.MTU),
	}
}

func ConvertVtepToVxlanLinuxConfig(vtep *VtepDbEntry) *vxlan_linux.VtepConfig {
	return &vxlan_linux.VtepConfig{
		VtepId:       vtep.VtepId,
		VxlanId:      vtep.VxlanId,
		VtepName:     vtep.VtepName,
		SrcIfName:    vtep.SrcIfName,
		UDP:          vtep.UDP,
		TTL:          vtep.TTL,
		TunnelSrcIp:  vtep.SrcIp,
		TunnelDstIp:  vtep.DstIp,
		VlanId:       vtep.VlanId,
		TunnelSrcMac: vtep.SrcMac,
		TunnelDstMac: vtep.DstMac,
	}
}

func ConvertVtepToVxlanAsicdConfig(vtep *VtepDbEntry) *asicdInt.Vtep {

	ifindex := int32(0)
	for _, pc := range PortConfigMap {
		if pc.Name == vtep.SrcIfName {
			ifindex = pc.IfIndex
		}

	}

	return &asicdInt.Vtep{
		IfIndex:    int32(vtep.VtepId),
		Vni:        int32(vtep.VxlanId),
		IfName:     vtep.VtepName,
		SrcIfIndex: ifindex,
		UDP:        int16(vtep.UDP),
		TTL:        int16(vtep.TTL),
		SrcIp:      vtep.SrcIp.String(),
		DstIp:      vtep.DstIp.String(),
		VlanId:     int16(vtep.VlanId),
		SrcMac:     vtep.SrcMac.String(),
	}
}

// look up the various other daemons based on c string
func GetClientPort(paramsFile string, c string) int {
	var clientsList []ClientJson

	bytes, err := ioutil.ReadFile(paramsFile)
	if err != nil {
		//StpLogger("ERROR", fmt.Sprintf("Error in reading configuration file:%s err:%s\n", paramsFile, err))
		return 0
	}

	err = json.Unmarshal(bytes, &clientsList)
	if err != nil {
		//StpLogger("ERROR", "Error in Unmarshalling Json")
		return 0
	}

	for _, client := range clientsList {
		if client.Name == c {
			return client.Port
		}
	}
	return 0
}

func ConstructPortConfigMap() {
	currMarker := asicdServices.Int(hwconst.MIN_SYS_PORTS)
	if asicdclnt.ClientHdl != nil {
		//StpLogger("INFO", "Calling asicd for port config")
		count := asicdServices.Int(hwconst.MAX_SYS_PORTS)
		for {
			bulkInfo, err := asicdclnt.ClientHdl.GetBulkPortState(currMarker, count)
			if err != nil {
				//StpLogger("ERROR", fmt.Sprintf("GetBulkPortState Error: %s", err))
				return
			}
			//StpLogger("INFO", fmt.Sprintf("Length of GetBulkPortState: %d", bulkInfo.Count))

			bulkCfgInfo, err := asicdclnt.ClientHdl.GetBulkPort(currMarker, count)
			if err != nil {
				//StpLogger("ERROR", fmt.Sprintf("Error: %s", err))
				return
			}

			//StpLogger("INFO", fmt.Sprintf("Length of GetBulkPortConfig: %d", bulkCfgInfo.Count))
			objCount := int(bulkInfo.Count)
			more := bool(bulkInfo.More)
			currMarker = asicdServices.Int(bulkInfo.EndIdx)
			for i := 0; i < objCount; i++ {
				ifindex := bulkInfo.PortStateList[i].IfIndex
				ent := PortConfigMap[ifindex]
				ent.PortNum = bulkInfo.PortStateList[i].PortNum
				ent.IfIndex = ifindex
				ent.Name = bulkInfo.PortStateList[i].Name
				ent.HardwareAddr, _ = net.ParseMAC(bulkCfgInfo.PortList[i].MacAddr)
				PortConfigMap[ifindex] = ent
				//StpLogger("INIT", fmt.Sprintf("Found Port %d IfIndex %d Name %s\n", ent.PortNum, ent.IfIndex, ent.Name))
			}
			if more == false {
				return
			}
		}
	}
}

// connect the clients
func ConnectToClients(paramsFile string) {
	allclientsnotconnect := false
	clientList := [3]string{"asicd", "ribd", "arpd"}
	for _, client := range clientList {
		port := GetClientPort(paramsFile, client)
		if port != 0 {
			for {
				if client == "asicd" {
					asicdclnt.Address = "localhost:" + strconv.Itoa(port)
					asicdclnt.Transport, asicdclnt.PtrProtocolFactory, _ = ipcutils.CreateIPCHandles(asicdclnt.Address)
					//StpLogger("INFO", fmt.Sprintf("found asicd at port %d Transport %#v PrtProtocolFactory %#v\n", port, asicdclnt.Transport, asicdclnt.PtrProtocolFactory))
					if asicdclnt.Transport != nil && asicdclnt.PtrProtocolFactory != nil {
						//StpLogger("INFO", "connecting to asicd\n")
						asicdclnt.ClientHdl = asicdServices.NewASICDServicesClientFactory(asicdclnt.Transport, asicdclnt.PtrProtocolFactory)
						asicdclnt.IsConnected = true
						// lets gather all info needed from asicd such as the port
						ConstructPortConfigMap()
						break
					} else {
						allclientsnotconnect = true
					}
				} else if client == "ribd" {
					ribdclnt.Address = "localhost:" + strconv.Itoa(port)
					ribdclnt.Transport, ribdclnt.PtrProtocolFactory, _ = ipcutils.CreateIPCHandles(ribdclnt.Address)
					//StpLogger("INFO", fmt.Sprintf("found asicd at port %d Transport %#v PrtProtocolFactory %#v\n", port, asicdclnt.Transport, asicdclnt.PtrProtocolFactory))
					if ribdclnt.Transport != nil && asicdclnt.PtrProtocolFactory != nil {
						//StpLogger("INFO", "connecting to asicd\n")
						ribdclnt.ClientHdl = ribd.NewRIBDServicesClientFactory(ribdclnt.Transport, ribdclnt.PtrProtocolFactory)
						ribdclnt.IsConnected = true
						break
					} else {
						allclientsnotconnect = true
					}
				} else if client == "arpd" {
					arpdclnt.Address = "localhost:" + strconv.Itoa(port)
					arpdclnt.Transport, arpdclnt.PtrProtocolFactory, _ = ipcutils.CreateIPCHandles(arpdclnt.Address)
					//StpLogger("INFO", fmt.Sprintf("found asicd at port %d Transport %#v PrtProtocolFactory %#v\n", port, asicdclnt.Transport, asicdclnt.PtrProtocolFactory))
					if arpdclnt.Transport != nil && arpdclnt.PtrProtocolFactory != nil {
						//StpLogger("INFO", "connecting to asicd\n")
						arpdclnt.ClientHdl = arpd.NewARPDServicesClientFactory(arpdclnt.Transport, arpdclnt.PtrProtocolFactory)
						arpdclnt.IsConnected = true
						break
					} else {
						allclientsnotconnect = true
					}
				}
				// lets delay to allow time for other processes to come up
				if allclientsnotconnect {
					time.Sleep(time.Millisecond * 500)
				}
			}
		}
	}
}

func asicDGetLinuxIfName(ifindex int32) string {

	if p, ok := PortConfigMap[ifindex]; ok {
		return p.Name
	}
	return ""
}

func asicDGetLoopbackInfo() (success bool, lbname string, mac net.HardwareAddr, ip net.IP) {
	// TODO this logic only assumes one loopback interface.  More logic is needed
	// to handle multiple  loopbacks configured.  The idea should be
	// that the lowest IP address is used.
	if asicdclnt.ClientHdl != nil {
		more := true
		for more {
			currMarker := asicdServices.Int(0)
			bulkInfo, err := asicdclnt.ClientHdl.GetBulkLogicalIntfState(currMarker, 5)
			if err == nil {
				objCount := int(bulkInfo.Count)
				more = bool(bulkInfo.More)
				currMarker = asicdServices.Int(bulkInfo.EndIdx)
				for i := 0; i < objCount; i++ {
					ifindex := bulkInfo.LogicalIntfStateList[i].IfIndex
					lbname = bulkInfo.LogicalIntfStateList[i].Name
					if pluginCommon.GetTypeFromIfIndex(ifindex) == commonDefs.IfTypeLoopback {
						mac, _ = net.ParseMAC(bulkInfo.LogicalIntfStateList[i].SrcMac)
						ipV4ObjMore := true
						ipV4ObjCurrMarker := asicdServices.Int(0)
						for ipV4ObjMore {
							ipV4BulkInfo, _ := asicdclnt.ClientHdl.GetBulkIPv4IntfState(ipV4ObjCurrMarker, 20)
							ipV4ObjCount := int(ipV4BulkInfo.Count)
							ipV4ObjCurrMarker = asicdServices.Int(bulkInfo.EndIdx)
							ipV4ObjMore = bool(ipV4BulkInfo.More)
							for j := 0; j < ipV4ObjCount; j++ {
								if ipV4BulkInfo.IPv4IntfStateList[j].IfIndex == ifindex {
									success = true
									ip = net.ParseIP(strings.Split(ipV4BulkInfo.IPv4IntfStateList[j].IpAddr, "/")[0])
									return success, lbname, mac, ip
								}
							}
						}
					}
				}
			}
		}
	}
	return success, lbname, mac, ip
}

func asicDCreateVxlan(vxlan *VxlanConfig) {
	// convert a vxland config to hw config
	if asicdclnt.ClientHdl != nil {
		asicdclnt.ClientHdl.CreateVxlan(ConvertVxlanConfigToVxlanAsicdConfig(vxlan))
	} else {

		// run standalone
		if softswitch == nil {
			softswitch = vxlan_linux.NewVxlanLinux(logger)
		}
		softswitch.CreateVxLAN(ConvertVxlanConfigToVxlanLinuxConfig(vxlan))
	}
}

func asicDDeleteVxlan(vxlan *VxlanConfig) {
	// convert a vxland config to hw config
	if asicdclnt.ClientHdl != nil {
		asicdclnt.ClientHdl.DeleteVxlan(ConvertVxlanConfigToVxlanAsicdConfig(vxlan))
	} else {
		// run standalone
		if softswitch != nil {
			softswitch.DeleteVxLAN(ConvertVxlanConfigToVxlanLinuxConfig(vxlan))
		}
	}
}

// asicDCreateVtep:
// Creates a VTEP interface with the ASICD.  Should create an interface within
// the HW as well as within Linux stack.   AsicD also requires that vlan membership is
// provisioned separately from VTEP.  The vlan in question is the VLAN found
// within the VXLAN header.
func asicDCreateVtep(vtep *VtepDbEntry) {
	// convert a vxland config to hw config
	if asicdclnt.ClientHdl != nil {

		// need to create a vlan membership of the vtep vlan Id
		if _, ok := PortVlanDb[vtep.VlanId]; !ok {
			v := &portVlanValue{
				ifIndex: vtep.SrcIfName,
				refCnt:  1,
			}
			PortVlanDb[vtep.VlanId] = append(PortVlanDb[vtep.VlanId], v)
			pbmp := fmt.Sprintf("%d", vtep.SrcIfName)

			asicdVlan := &asicdServices.Vlan{
				VlanId:   int32(vtep.VlanId),
				IntfList: pbmp,
			}
			asicdclnt.ClientHdl.CreateVlan(asicdVlan)

		} else {
			portExists := -1
			for i, p := range PortVlanDb[vtep.VlanId] {
				if p.ifIndex == vtep.SrcIfName {
					portExists = i
					break
				}
			}
			if portExists == -1 {
				oldpbmp := ""
				for _, p := range PortVlanDb[vtep.VlanId] {
					oldpbmp += fmt.Sprintf("%s", p.ifIndex)
				}
				v := &portVlanValue{
					ifIndex: vtep.SrcIfName,
					refCnt:  1,
				}
				PortVlanDb[vtep.VlanId] = append(PortVlanDb[vtep.VlanId], v)
				newpbmp := ""
				for _, p := range PortVlanDb[vtep.VlanId] {
					newpbmp += fmt.Sprintf("%s", p.ifIndex)
				}

				oldAsicdVlan := &asicdServices.Vlan{
					VlanId:   int32(vtep.VlanId),
					IntfList: oldpbmp,
				}
				newAsicdVlan := &asicdServices.Vlan{
					VlanId:   int32(vtep.VlanId),
					IntfList: newpbmp,
				}
				// note if the thrift attribute id's change then
				// this attr may need to be updated
				attrset := []bool{false, true, false}
				asicdclnt.ClientHdl.UpdateVlan(oldAsicdVlan, newAsicdVlan, attrset)
			} else {
				v := PortVlanDb[vtep.VlanId][portExists]
				v.refCnt++
				PortVlanDb[vtep.VlanId][portExists] = v
			}
		}
		// create the vtep
		asicdclnt.ClientHdl.CreateVxlanVtep(ConvertVtepToVxlanAsicdConfig(vtep))
	} else {
		// run standalone
		if softswitch == nil {
			softswitch = vxlan_linux.NewVxlanLinux(logger)
		}
		softswitch.CreateVtep(ConvertVtepToVxlanLinuxConfig(vtep))
	}
}

// asicDDeleteVtep:
// Delete a VTEP interface with the ASICD.  Should create an interface within
// the HW as well as within Linux stack. AsicD also requires that vlan membership is
// provisioned separately from VTEP.  The vlan in question is the VLAN found
// within the VXLAN header.
func asicDDeleteVtep(vtep *VtepDbEntry) {
	// convert a vxland config to hw config
	if asicdclnt.ClientHdl != nil {
		// delete the vtep
		asicdclnt.ClientHdl.DeleteVxlanVtep(ConvertVtepToVxlanAsicdConfig(vtep))

		// update the vlan the vtep was using
		if _, ok := PortVlanDb[vtep.VlanId]; ok {
			portExists := -1
			for i, p := range PortVlanDb[vtep.VlanId] {
				if p.ifIndex == vtep.SrcIfName {
					portExists = i
					break
				}
			}
			if portExists != -1 {
				v := PortVlanDb[vtep.VlanId][portExists]
				v.refCnt--
				PortVlanDb[vtep.VlanId][portExists] = v

				// lets remove this port from the vlan
				if v.refCnt == 0 {
					oldpbmp := ""
					for _, p := range PortVlanDb[vtep.VlanId] {
						oldpbmp += fmt.Sprintf("%s", p.ifIndex)
					}
					// remove from local list
					PortVlanDb[vtep.VlanId] = append(PortVlanDb[vtep.VlanId][:portExists], PortVlanDb[vtep.VlanId][portExists+1:]...)
					newpbmp := ""
					for _, p := range PortVlanDb[vtep.VlanId] {
						newpbmp += fmt.Sprintf("%s", p.ifIndex)
					}

					oldAsicdVlan := &asicdServices.Vlan{
						VlanId:   int32(vtep.VlanId),
						IntfList: oldpbmp,
					}
					newAsicdVlan := &asicdServices.Vlan{
						VlanId:   int32(vtep.VlanId),
						IntfList: newpbmp,
					}
					// note if the thrift attribute id's change then
					// this attr may need to be updated
					attrset := []bool{false, true, false}
					asicdclnt.ClientHdl.UpdateVlan(oldAsicdVlan, newAsicdVlan, attrset)
				}
				// lets remove the vlan
				if len(PortVlanDb[vtep.VlanId]) == 0 {

					asicdVlan := &asicdServices.Vlan{
						VlanId: int32(vtep.VlanId),
					}
					asicdclnt.ClientHdl.DeleteVlan(asicdVlan)
					delete(PortVlanDb, vtep.VlanId)

				}
			}
		}
	} else {
		// run standalone
		if softswitch != nil {
			softswitch.DeleteVtep(ConvertVtepToVxlanLinuxConfig(vtep))
		}
	}
}

func asicDLearnFwdDbEntry(mac net.HardwareAddr, vtepName string, ifindex int32) {
	macstr := mac.String()
	// convert a vxland config to hw config
	if asicdclnt.ClientHdl != nil {
		//asicdclnt.ClientHdl.DeleteVxlanVtep(ConvertVtepConfigToVxlanAsicdConfig(vtep))
	} else {
		// run standalone
		if softswitch != nil {
			softswitch.LearnFdbVtep(macstr, vtepName, ifindex)
		}
	}

}

// rib holds the next hop info, and asicd holds the mac address
func ribDGetNextHopInfo(ip net.IP, nexthopchan chan net.IP) {
	if ribdclnt.ClientHdl != nil {
		nexthopinfo, err := ribdclnt.ClientHdl.GetRouteReachabilityInfo(ip.String())
		if err == nil {
			nexthopip := net.ParseIP(nexthopinfo.NextHopIp)
			// lets let RIB notify us if there is a change in next hop
			ribdclnt.ClientHdl.TrackReachabilityStatus(ip.String(), "VXLAND", "add")
			nexthopchan <- nexthopip
		}
	}
}

func arpDResolveNextHopMac(nexthopip net.IP, macchan chan net.HardwareAddr) {
	if arpdclnt.ClientHdl != nil {
		arpentrystate, err := arpdclnt.ClientHdl.GetArpEntryState(nexthopip.String())
		if err == nil {
			nexthopip, _ := net.ParseMAC(arpentrystate.MacAddr)
			macchan <- nexthopip
		}
	}
}
