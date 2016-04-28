// config.go
// Config entry is based on thrift data structures.
package vxlan

import (
	//"fmt"
	"net"
	"reflect"
	"strings"
	"vxland"
)

const (
	VxlanCommandCreate = iota + 1
	VxlanCommandDelete
	VxlanCommandUpdate
)

type VxLanConfigChannels struct {
	Vxlancreate               chan VxlanConfig
	Vxlandelete               chan VxlanConfig
	Vxlanupdate               chan VxlanUpdate
	Vtepcreate                chan VtepConfig
	Vtepdelete                chan VtepConfig
	Vtepupdate                chan VtepUpdate
	VxlanAccessPortVlanUpdate chan VxlanAccessPortVlan
	VxlanNextHopUpdate        chan VxlanNextHopIp
	VxlanPortCreate           chan PortConfig
	Vxlanintfinfo             chan VxlanIntfInfo
}

type VxlanIntfInfo struct {
	Command  int
	IntfName string
	IfIndex  int32
	Mac      net.HardwareAddr
	Ip       net.IP
}

type VxlanNextHopIp struct {
	Command   int
	Ip        net.IP
	Intf      int32
	IntfName  string
	NextHopIp net.IP
}

type VxlanAccessPortVlan struct {
	Command  int
	VlanId   uint16
	IntfList []int32
}

type VxlanUpdate struct {
	Oldconfig VxlanConfig
	Newconfig VxlanConfig
	Attr      []bool
}

type VtepUpdate struct {
	Oldconfig VtepConfig
	Newconfig VtepConfig
	Attr      []bool
}

// bridge for the VNI
type VxlanConfig struct {
	VNI    uint32
	VlanId uint16 // used to tag inner ethernet frame when egressing
	Group  net.IP // multicast group IP
	MTU    uint32 // MTU size for each VTEP
}

type PortConfig struct {
	Name         string
	HardwareAddr net.HardwareAddr
	Speed        int32
	PortNum      int32
	IfIndex      int32
}

// tunnel endpoint for the VxLAN
type VtepConfig struct {
	Vni                   uint32           `SNAPROUTE: KEY` //VxLAN ID.
	VtepName              string           //VTEP instance name.
	SrcIfName             string           //Source interface ifIndex.
	UDP                   uint16           //vxlan udp port.  Deafult is the iana default udp port
	TTL                   uint16           //TTL of the Vxlan tunnel
	TOS                   uint16           //Type of Service
	InnerVlanHandlingMode int32            //The inner vlan tag handling mode.
	Learning              bool             //specifies if unknown source link layer  addresses and IP addresses are entered into the VXLAN  device forwarding database.
	Rsc                   bool             //specifies if route short circuit is turned on.
	L2miss                bool             //specifies if netlink LLADDR miss notifications are generated.
	L3miss                bool             //specifies if netlink IP ADDR miss notifications are generated.
	TunnelSrcIp           net.IP           //Source IP address for the static VxLAN tunnel
	TunnelDstIp           net.IP           //Destination IP address for the static VxLAN tunnel
	VlanId                uint16           //Vlan Id to encapsulate with the vtep tunnel ethernet header
	TunnelSrcMac          net.HardwareAddr //Src Mac assigned to the VTEP within this VxLAN. If an address is not assigned the the local switch address will be used.
	TunnelDstMac          net.HardwareAddr // Optional - may be looked up based on TunnelNextHopIp
	TunnelNextHopIP       net.IP           // NextHopIP is used to find the DMAC for the tunnel within Asicd
}

func ConvertInt32ToBool(val int32) bool {
	if val == 0 {
		return false
	}
	return true
}

// ConvertVxlanInstanceToVxlanConfig:
// Convert thrift struct to vxlan config
func ConvertVxlanInstanceToVxlanConfig(c *vxland.VxlanInstance) (*VxlanConfig, error) {

	return &VxlanConfig{
		VNI:    uint32(c.Vni),
		VlanId: uint16(c.VlanId),
	}, nil
}

func getVtepName(intf string) string {
	vtepName := intf
	if !strings.Contains("vtep", intf) {
		vtepName = "vtep" + intf
	}
	return vtepName
}

// ConvertVxlanVtepInstanceToVtepConfig:
// Convert thrift struct to vxlan config
func ConvertVxlanVtepInstanceToVtepConfig(c *vxland.VxlanVtepInstance) (*VtepConfig, error) {

	var mac net.HardwareAddr
	var ip net.IP
	var name string
	//var ok bool
	vtepName := getVtepName(c.Intf)
	name = c.IntfRef
	ip = net.ParseIP(c.SrcIp)

	/* TODO need to create a generic way to get an interface name, mac, ip
	if c.SrcIp == "0.0.0.0" && c.IntfRef != "" {
		// need to get the appropriate IntfRef type
		ok, name, mac, ip = snapclient.asicDGetLoopbackInfo()
		if !ok {
			errorstr := "VTEP: Src Tunnel Info not provisioned yet, loopback intf needed"
			logger.Info(errorstr)
			return &VtepConfig{}, errors.New(errorstr)
		}
		fmt.Println("loopback info:", name, mac, ip)
		if c.SrcIp != "0.0.0.0" {
			ip = net.ParseIP(c.SrcIp)
		}
		logger.Info(fmt.Sprintf("Forcing Vtep %s to use Lb %s SrcMac %s Ip %s", vtepName, name, mac, ip))
	}
	*/

	return &VtepConfig{
		Vni:       uint32(c.Vni),
		VtepName:  vtepName,
		SrcIfName: name,
		UDP:       uint16(c.DstUDP),
		TTL:       uint16(c.TTL),
		TOS:       uint16(c.TOS),
		InnerVlanHandlingMode: c.InnerVlanHandlingMode,
		TunnelSrcIp:           ip,
		TunnelDstIp:           net.ParseIP(c.DstIp),
		VlanId:                uint16(c.VlanId),
		TunnelSrcMac:          mac,
	}, nil
}

func (s *VXLANServer) updateThriftVxLAN(c *VxlanUpdate) {
	objTyp := reflect.TypeOf(c.Oldconfig)

	// important to note that the attrset starts at index 0 which is the BaseObj
	// which is not the first element on the thrift obj, thus we need to skip
	// this attribute
	for i := 0; i < objTyp.NumField(); i++ {
		objName := objTyp.Field(i).Name
		if c.Attr[i] {

			if objName == "VxlanId" {
				// TODO
			}
			if objName == "McDestIp" {
				// TODO
			}
			if objName == "VlanId" {
				// TODO
			}
			if objName == "Mtu" {
				// TODO
			}
		}
	}
}

func (s *VXLANServer) updateThriftVtep(c *VtepUpdate) {
	objTyp := reflect.TypeOf(c.Oldconfig)

	// important to note that the attrset starts at index 0 which is the BaseObj
	// which is not the first element on the thrift obj, thus we need to skip
	// this attribute
	for i := 0; i < objTyp.NumField(); i++ {
		objName := objTyp.Field(i).Name
		if c.Attr[i] {

			if objName == "InnerVlanHandlingMode" {
				// TODO
			}
			if objName == "UDP" {
				// TODO
			}
			if objName == "TunnelSourceIp" {
				// TODO
			}
			if objName == "SrcMac" {
				// TODO
			}
			if objName == "L2miss" {
				// TODO
			}
			if objName == "TOS" {
				// TODO
			}
			if objName == "VxlanId" {
				// TODO
			}
			if objName == "VtepName" {
				// TODO
			}
			if objName == "VlanId" {
				// TODO
			}
			if objName == "Rsc" {
				// TODO
			}
			if objName == "VtepId" {
				// TODO
			}
			if objName == "SrcIfIndex" {
				// TODO
			}
			if objName == "L3miss" {
				// TODO
			}
			if objName == "Learning" {
				// TODO
			}
			if objName == "TTL" {
				// TODO
			}
			if objName == "TunnelDestinationIp" {
				// TODO
			}
		}
	}
}

func (s *VXLANServer) ConfigListener() {

	s.Configchans = &VxLanConfigChannels{
		Vxlancreate:               make(chan VxlanConfig, 0),
		Vxlandelete:               make(chan VxlanConfig, 0),
		Vxlanupdate:               make(chan VxlanUpdate, 0),
		Vtepcreate:                make(chan VtepConfig, 0),
		Vtepdelete:                make(chan VtepConfig, 0),
		Vtepupdate:                make(chan VtepUpdate, 0),
		VxlanAccessPortVlanUpdate: make(chan VxlanAccessPortVlan, 0),
		VxlanNextHopUpdate:        make(chan VxlanNextHopIp, 0),
		VxlanPortCreate:           make(chan PortConfig, 0),
	}

	go func(cc *VxLanConfigChannels) {
		for {
			select {

			case vxlan := <-cc.Vxlancreate:
				CreateVxLAN(&vxlan)

			case vxlan := <-cc.Vxlandelete:
				DeleteVxLAN(&vxlan)

			case <-cc.Vxlanupdate:
				//s.UpdateThriftVxLAN(&vxlan)

			case vtep := <-cc.Vtepcreate:
				CreateVtep(&vtep)

			case vtep := <-cc.Vtepdelete:
				DeleteVtep(&vtep)

			case <-cc.Vtepupdate:
				//s.UpdateThriftVtep(&vtep)

			case <-cc.VxlanAccessPortVlanUpdate:
				// updates from client which are post create of vxlan

			case ipinfo := <-cc.VxlanNextHopUpdate:
				// updates from client which are triggered post create of vtep
				reachable := false
				if ipinfo.Command == VxlanCommandCreate {
					reachable = true
				}
				//ip := net.ParseIP(fmt.Sprintf("%s.%s.%s.%s", uint8(ipinfo.Ip>>24&0xff), uint8(ipinfo.Ip>>16&0xff), uint8(ipinfo.Ip>>8&0xff), uint8(ipinfo.Ip>>0&0xff)))
				s.HandleNextHopChange(ipinfo.Ip, ipinfo.NextHopIp, reachable)

			case port := <-cc.VxlanPortCreate:
				// store all the valid physical ports
				if p, ok := PortConfigMap[port.IfIndex]; ok {
					var portcfg = &PortConfig{}
					CopyStruct(p, portcfg)
					PortConfigMap[port.IfIndex] = portcfg

					// TODO remove this once code exists to
					// only listen on ports where a vtep's next hop
					// resides
					VxlanPortRxTx(p.Name, 4789)
				}
			case intfinfo := <-cc.Vxlanintfinfo:
				for _, vtep := range GetVtepDB() {
					if vtep.SrcIfName == intfinfo.IntfName {
						vtep.intfinfochan <- intfinfo
					}
				}
			}
		}
	}(s.Configchans)
}
