// vtepdb.go
package vxlan

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

const (
	VtepStatusUp             vtepStatus = "UP"
	VtepStatusDown                      = "DOWN"
	VtepStatusAdminDown                 = "ADMIN DOWN"
	VtepStatusIncomplete                = "INCOMPLETE PROV"
	VtepStatusNextHopUnknown            = "NEXT HOP UKNOWN"
	VtepStatusArpUnresolved             = "ARP UNRESOLVED"
	VtepStatusConfigPending             = "CONFIG PENDING"
)

type VtepDbKey struct {
	VtepId uint32
}

type vtepVniCMACToVtepKey struct {
	Vni uint32
	Mac net.HardwareAddr
}

type vtepStatus string

type VtepDbEntry struct {
	VtepId      uint32
	VxlanId     uint32
	VtepName    string
	SrcIfName   string
	UDP         uint16
	TTL         uint16
	SrcIp       net.IP
	DstIp       net.IP
	VlanId      uint16
	SrcMac      net.HardwareAddr
	DstMac      net.HardwareAddr
	VtepIfIndex int32
	NextHopIp   net.IP

	Status vtepStatus

	// handle used to rx/tx packets to linux if
	handle *pcap.Handle

	server *VXLANServer

	rxpkts uint64
	txpkts uint64

	nexthopchan chan net.IP
	macchan     chan net.HardwareAddr
	hwconfig    chan bool
	killroutine chan bool

	retrytimer *time.Timer
}

// pcap handle (vtep) per source ip defined
type VtepVniSrcIpEntry struct {
	// handle used to rx/tx packets from other applications
	handle *pcap.Handle
}

type SrcIfIndexEntry struct {
	IfIndex int32
	// handle used to rx/tx packets from/to linux if
	handle *pcap.Handle
}

// vtep id to vtep data
var vtepDB map[VtepDbKey]*VtepDbEntry

// vni + customer mac to vtepId
//var fdbDb map[vtepVniCMACToVtepKey]VtepDbKey

// db to hold vni ip to pcap handle
var vtepAppPcap []VtepVniSrcIpEntry

var VxlanVtepSrcIp net.IP
var VxlanVtepSrcNetMac net.HardwareAddr
var VxlanVtepSrcMac [6]uint8
var VxlanVtepRxTx = CreateVtepRxTx

func (vtep *VtepDbEntry) GetRxStats() uint64 {
	return vtep.rxpkts
}

func (vtep *VtepDbEntry) GetTxStats() uint64 {
	return vtep.txpkts
}

func GetVtepDB() map[VtepDbKey]*VtepDbEntry {
	return vtepDB
}

func GetVtepDBEntry(key *VtepDbKey) *VtepDbEntry {
	if vtep, ok := vtepDB[*key]; ok {
		return vtep
	}
	return nil
}

/* TODO may need to keep a table to map customer macs to vtep
type srcMacVtepMap struct {
	SrcMac      net.HardwareAddr
	VtepIfIndex int32
}
*/

func NewVtepDbEntry(c *VtepConfig) *VtepDbEntry {
	vtep := &VtepDbEntry{
		VtepId:  c.VtepId,
		VxlanId: c.VxlanId,
		// TODO if we are running in hw linux vs proxy then this should not be + Int
		VtepName: c.VtepName + "Int",
		//VtepName:  c.VtepName,
		SrcIfName: c.SrcIfName,
		UDP:       c.UDP,
		TTL:       c.TTL,
		DstIp:     c.TunnelDstIp,
		SrcIp:     c.TunnelSrcIp,
		SrcMac:    c.TunnelSrcMac,
		DstMac:    c.TunnelDstMac,
		VlanId:    c.VlanId,
		Status:    VtepStatusNextHopUnknown,
	}

	return vtep
}

func (vtep *VtepDbEntry) VtepFsmCleanup() {
	vtep.retrytimer.Stop()
	close(vtep.nexthopchan)
	close(vtep.macchan)
	close(vtep.hwconfig)
	close(vtep.killroutine)
}

// used to resolve mac/ip of the next hop
func (vtep *VtepDbEntry) VtepFsm() {

	vtep.nexthopchan = make(chan net.IP, 1)
	vtep.macchan = make(chan net.HardwareAddr, 1)
	vtep.hwconfig = make(chan bool, 1)
	vtep.killroutine = make(chan bool, 1)

	// TODO, what should this time be
	retrytime := time.Millisecond * 50

	vtep.retrytimer = time.NewTimer(retrytime)

	go func() {

		for {
			select {
			case <-vtep.retrytimer.C:
				if vtep.Status == VtepStatusNextHopUnknown {
					hwGetNextHop(vtep.DstIp, vtep.nexthopchan)
				} else if vtep.Status == VtepStatusArpUnresolved {
					hwResolveMac(vtep.NextHopIp, vtep.macchan)
				}

				vtep.retrytimer.Reset(retrytime)

			case ip, _ := <-vtep.nexthopchan:
				// stop the timer if we have the response
				vtep.retrytimer.Stop()
				if vtep.Status == VtepStatusNextHopUnknown {
					vtep.NextHopIp = ip
					logger.Info(fmt.Sprintf("%s: found dstip %s next hop %s", strings.TrimRight(vtep.VtepName, "Int"), vtep.DstIp, vtep.NextHopIp))
					vtep.Status = VtepStatusArpUnresolved
					hwResolveMac(vtep.NextHopIp, vtep.macchan)
				}
				vtep.retrytimer.Reset(retrytime)

			case mac, _ := <-vtep.macchan:
				vtep.retrytimer.Stop()

				fmt.Printf("%s: resolved mac %s for next hop ip %#v status=%d", strings.TrimRight(vtep.VtepName, "Int"), vtep.DstMac, vtep.NextHopIp, vtep.Status)

				if vtep.Status == VtepStatusArpUnresolved {
					vtep.DstMac = mac
					//logger.Info(fmt.Sprintf("%s: resolved mac %s for next hop ip %#v", strings.TrimRight(vtep.VtepName, "Int"), vtep.DstMac, vtep.NextHopIp))
					vtep.Status = VtepStatusConfigPending
					vtep.hwconfig <- true
				} else {
					vtep.retrytimer.Reset(retrytime)
				}

			case _, ok := <-vtep.hwconfig:
				if ok {
					// TODO this is only necessary in "proxy" mode
					VxlanPortRxTx(vtep.SrcIfName, vtep.UDP)
					// lets create the packet listener for the rx/tx packets
					VxlanVtepRxTx(vtep)
					// we are commit to the hw
					vtep.Status = VtepStatusUp
					// create vtep resources in hw
					hwCreateVtep(vtep)

				} else {
					// channel closed lets return
					return
				}
			}
		}
	}()

	vtep.Status = VtepStatusNextHopUnknown
	if vtep.DstMac.String() == "" {
		// lets try and resolve the mac
		hwGetNextHop(vtep.DstIp, vtep.nexthopchan)
	} else {
		fmt.Println("DstMac provisioned by user")
		// no need to get next hop the user appears to know what the next hop mac is
		vtep.Status = VtepStatusArpUnresolved
		vtep.macchan <- vtep.DstMac
	}
}

func CreateVtep(c *VtepConfig) *VtepDbEntry {

	vtep := saveVtepConfigData(c)

	// lets resolve the mac address
	vtep.VtepFsm()

	return vtep
}

func DeleteVtep(c *VtepConfig) {

	key := VtepDbKey{
		VtepId: c.VtepId,
	}

	if vtep, ok := vtepDB[key]; ok {
		// delete vtep resources in hw
		hwDeleteVtep(vtep)
		if vtep.handle != nil {
			vtep.handle.Close()
		}
		delete(vtepDB, key)
	}

	DeletePort(c.SrcIfName, c.UDP)

}

func saveVtepConfigData(c *VtepConfig) *VtepDbEntry {
	key := VtepDbKey{
		VtepId: c.VtepId,
	}
	vtep, ok := vtepDB[key]
	if !ok {
		vtep = NewVtepDbEntry(c)
		vtepDB[key] = vtep
	}
	return vtep
}

func SaveVtepSrcMacSrcIp(paramspath string) {
	var cfgFile cfgFileJson
	asicdconffilename := paramspath + "asicd.conf"
	cfgFileData, err := ioutil.ReadFile(asicdconffilename)
	if err != nil {
		logger.Info("Error reading config file - asicd.conf")
		return
	}
	err = json.Unmarshal(cfgFileData, &cfgFile)
	if err != nil {
		logger.Info("Error parsing config file")
		return
	}

	VxlanVtepSrcNetMac, _ := net.ParseMAC(cfgFile.SwitchMac)
	VxlanVtepSrcMac = [6]uint8{VxlanVtepSrcNetMac[0], VxlanVtepSrcNetMac[1], VxlanVtepSrcNetMac[2], VxlanVtepSrcNetMac[3], VxlanVtepSrcNetMac[4], VxlanVtepSrcNetMac[5]}

}

func CreateVtepRxTx(vtep *VtepDbEntry) {
	vtep.createVtepSenderListener()
}

func (vtep *VtepDbEntry) createVtepSenderListener() error {

	// TODO need to revisit the timeout interval in case of processing lots of
	// data frames
	handle, err := pcap.OpenLive(vtep.VtepName, 65536, false, 50*time.Millisecond)
	if err != nil {
		logger.Err(fmt.Sprintf("%s: Error opening pcap.OpenLive %s", vtep.VtepName, err))
		return err
	}
	logger.Info(fmt.Sprintf("Creating VXLAN Listener for intf ", vtep.VtepName))
	vtep.handle = handle
	src := gopacket.NewPacketSource(vtep.handle, layers.LayerTypeEthernet)
	in := src.Packets()

	go func(rxchan chan gopacket.Packet) {
		for {
			select {
			// packets received from applications which should be sent out
			case packet, ok := <-rxchan:
				if ok {
					if !vtep.filterPacket(packet) {
						go vtep.encapAndDispatchPkt(packet)
					}
				} else {
					// channel closed
					return
				}
			}
		}
	}(in)

	return nil
}

// do not process packets which contain the vtep src mac
func (vtep *VtepDbEntry) filterPacket(packet gopacket.Packet) bool {

	ethernetL := packet.Layer(layers.LayerTypeEthernet)
	if ethernetL != nil {
		ethernet := ethernetL.(*layers.Ethernet)
		if ethernet.SrcMAC[0] == vtep.SrcMac[0] &&
			ethernet.SrcMAC[1] == vtep.SrcMac[1] &&
			ethernet.SrcMAC[2] == vtep.SrcMac[2] &&
			ethernet.SrcMAC[3] == vtep.SrcMac[3] &&
			ethernet.SrcMAC[4] == vtep.SrcMac[4] &&
			ethernet.SrcMAC[5] == vtep.SrcMac[5] {
			return true
		}
	}
	return false
}

func (vtep *VtepDbEntry) snoop(data []byte) {
	p2 := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
	ethernetL := p2.Layer(layers.LayerTypeEthernet)
	if ethernetL != nil {
		ethernet, _ := ethernetL.(*layers.Ethernet)
		learnmac := ethernet.SrcMAC
		// fdb entry mac -> vtep ip interface
		logger.Info(fmt.Sprintf("Learning mac", learnmac, "against", strings.TrimRight(vtep.VtepName, "Int")))
		asicDLearnFwdDbEntry(learnmac, vtep.VtepName, vtep.VtepIfIndex)
	}

}

func (vtep *VtepDbEntry) decapAndDispatchPkt(packet gopacket.Packet) {

	vxlanLayer := packet.Layer(layers.LayerTypeVxlan)
	if vxlanLayer != nil {
		vxlan := vxlanLayer.(*layers.VXLAN)
		buf := vxlan.LayerPayload()
		logger.Info(fmt.Sprintf("Sending Packet to %s %#v", vtep.VtepName, buf))
		vtep.snoop(buf)
		if err := vtep.handle.WritePacketData(buf); err != nil {
			logger.Err("Error writing packet to interface")
		}
	}
}

func (vtep *VtepDbEntry) encapAndDispatchPkt(packet gopacket.Packet) {
	// every vtep is tied to a port
	if p, ok := portDB[vtep.SrcIfName]; ok {
		phandle := p.handle
		// outer ethernet header
		eth := layers.Ethernet{
			SrcMAC:       vtep.SrcMac,
			DstMAC:       vtep.DstMac,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := layers.IPv4{
			Version:    4,
			IHL:        20,
			TOS:        0,
			Length:     120,
			Id:         0xd2c0,
			Flags:      layers.IPv4DontFragment, //IPv4Flag
			FragOffset: 0,                       //uint16
			TTL:        255,
			Protocol:   layers.IPProtocolUDP, //IPProtocol
			SrcIP:      vtep.SrcIp,
			DstIP:      vtep.DstIp,
		}

		udp := layers.UDP{
			SrcPort: layers.UDPPort(vtep.UDP), // TODO need a src port
			DstPort: layers.UDPPort(vtep.UDP),
			Length:  100,
		}
		udp.SetNetworkLayerForChecksum(&ip)

		vxlan := layers.VXLAN{
			BaseLayer: layers.BaseLayer{
				Payload: packet.Data(),
			},
			Flags: 0x08,
		}
		vxlan.SetVNI(vtep.VxlanId)

		// Set up buffer and options for serialization.
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		// Send one packet for every address.
		gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &vxlan)
		logger.Info(fmt.Sprintf("Rx Packet now encapsulating and sending packet to if", vtep.SrcIfName, buf))
		if err := phandle.WritePacketData(buf.Bytes()); err != nil {
			logger.Err("Error writing packet to interface")
			return
		}
		vtep.txpkts++
	}
}
