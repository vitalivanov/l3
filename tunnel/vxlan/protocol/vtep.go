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
	"sync"
	"time"
)

const (
	VtepStatusUp             vtepStatus = "UP"
	VtepStatusDown                      = "DOWN"
	VtepStatusAdminDown                 = "ADMIN DOWN"
	VtepStatusIncomplete                = "INCOMPLETE VTEP PROV"
	VtepStatusDetached                  = "ICOMPLETE VTEP VXLAN NOT PROV"
	VtepStatusIntfUnknown               = "SRC INTF UNKNOWN"
	VtepStatusNextHopUnknown            = "NEXT HOP UKNOWN"
	VtepStatusArpUnresolved             = "ARP UNRESOLVED"
	VtepStatusConfigPending             = "CONFIG PENDING"
)

type VtepDbKey struct {
	name string
}

type vtepVniCMACToVtepKey struct {
	Vni uint32
	Mac net.HardwareAddr
}

type vtepStatus string

type VtepDbEntry struct {
	Vni         uint32
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
	VtepHandleName string
	handle         *pcap.Handle

	server *VXLANServer

	rxpkts uint64
	txpkts uint64

	nexthopchan  chan net.IP
	macchan      chan net.HardwareAddr
	hwconfig     chan bool
	killroutine  chan bool
	intfinfochan chan VxlanIntfInfo

	// number of ticks before hw was able to come up
	ticksTillConfig int

	retrytimer *time.Timer

	// wait group used to help sync on cleanup of FSM
	wg sync.WaitGroup
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
		Vni: c.Vni,
		// TODO if we are running in hw linux vs proxy then this should not be + Int
		VtepName:       c.VtepName,
		VtepHandleName: c.VtepName + "Int",
		//VtepName:  c.VtepName,
		SrcIfName: c.SrcIfName,
		UDP:       c.UDP,
		TTL:       c.TTL,
		DstIp:     c.TunnelDstIp,
		SrcIp:     c.TunnelSrcIp,
		SrcMac:    c.TunnelSrcMac,
		DstMac:    c.TunnelDstMac,
		VlanId:    c.VlanId,
		Status:    VtepStatusIncomplete,
	}

	return vtep
}

func (vtep *VtepDbEntry) VtepFsmCleanup() {
	// FSM may not have been launched
	// lets based this determination based on
	// the retry timer
	if vtep.retrytimer != nil {
		vtep.retrytimer.Stop()
		close(vtep.macchan)
		close(vtep.hwconfig)
		close(vtep.killroutine)
		vtep.wg.Wait()
	}
}

// VtepFsm:
// FSM used to resolve mac/ip of the next hop
func (vtep *VtepDbEntry) VtepFsm() {

	vtep.nexthopchan = make(chan net.IP, 1)
	vtep.macchan = make(chan net.HardwareAddr, 1)
	vtep.hwconfig = make(chan bool, 1)
	vtep.killroutine = make(chan bool, 1)
	vtep.intfinfochan = make(chan VxlanIntfInfo, 1)

	// TODO, what should this time be
	retrytime := time.Millisecond * 50

	vtep.retrytimer = time.NewTimer(retrytime)

	// add a wait group to help with cleanup of FSM
	vtep.wg.Add(1)

	go func() {
		logger.Info(fmt.Sprintf("Starting FSM for vtep %s", vtep.VtepName))
		defer vtep.wg.Done()
		for {
			select {
			case <-vtep.retrytimer.C:
				if _, ok := GetVxlanDB()[vtep.Vni]; ok {
					for _, client := range ClientIntf {
						if vtep.Status == VtepStatusIncomplete {
							// get the interface which contains ip/mac for use
							// by this vtep
							client.GetIntfInfo(vtep.SrcIfName, vtep.intfinfochan)
						} else if vtep.Status == VtepStatusNextHopUnknown {
							// determine the next hop ip based on the dst ip
							client.GetNextHopInfo(vtep.DstIp, vtep.nexthopchan)
						} else if vtep.Status == VtepStatusArpUnresolved {
							// resolve the next hop mac based on the next hop ip
							client.ResolveNextHopMac(vtep.NextHopIp, vtep.macchan)
						}
					}
				}
				vtep.ticksTillConfig++
				vtep.retrytimer.Reset(retrytime)

			case intfinfo := <-vtep.intfinfochan:
				vtep.retrytimer.Stop()
				logger.Info(fmt.Sprintf("infinfochan rx: status %s", vtep.Status))
				if vtep.Status == VtepStatusIncomplete {
					// next state
					vtep.Status = VtepStatusNextHopUnknown

					// save off info related to the source
					vtep.SrcIfName = intfinfo.IntfName
					vtep.SrcIp = intfinfo.Ip
					vtep.SrcMac = intfinfo.Mac

					// lets try and resolve the next hop
					for _, client := range ClientIntf {
						client.GetNextHopInfo(vtep.DstIp, vtep.nexthopchan)
					}
				}

				vtep.retrytimer.Reset(retrytime)
			case ip, _ := <-vtep.nexthopchan:
				// stop the timer if we have the response
				vtep.retrytimer.Stop()
				if vtep.Status == VtepStatusNextHopUnknown {
					vtep.NextHopIp = ip
					// TODO need create a port listener per next hop interface
					// lets start listening on this port for VXLAN frames
					// Call will protect against multiple calls to same port
					//CreatePort(VxlanNextHopIp.Intf, vtep.UDP)
					logger.Info(fmt.Sprintf("%s: found dstip %s next hop %s", strings.TrimRight(vtep.VtepName, "Int"), vtep.DstIp, vtep.NextHopIp))
					// next state
					vtep.Status = VtepStatusArpUnresolved
					for _, client := range ClientIntf {
						client.ResolveNextHopMac(vtep.NextHopIp, vtep.macchan)
					}
				}
				vtep.retrytimer.Reset(retrytime)

			case mac, _ := <-vtep.macchan:
				vtep.retrytimer.Stop()

				if vtep.Status == VtepStatusArpUnresolved {
					vtep.DstMac = mac
					vtep.Status = VtepStatusConfigPending
					logger.Info(fmt.Sprintf("%s: resolved mac %s for next hop ip %s status %s", strings.TrimRight(vtep.VtepName, "Int"), vtep.DstMac, vtep.NextHopIp, vtep.Status))
					// protect against vxlan not existing yet
					if _, ok := GetVxlanDB()[vtep.Vni]; ok {
						vtep.hwconfig <- true
					}
				} else {
					vtep.retrytimer.Reset(retrytime)
				}

			case _, ok := <-vtep.hwconfig:
				if ok {
					// lets create the packet listener for the rx/tx packets
					VxlanVtepRxTx(vtep)
					// we are commit to the hw
					vtep.Status = VtepStatusUp
					// create vtep resources in hw
					for _, client := range ClientIntf {
						client.CreateVtep(vtep)
					}
					vtep.retrytimer.Stop()

				} else {
					// channel closed lets return
					logger.Info(fmt.Sprintf("Stopping FSM for vtep %s", vtep.VtepName))
					return
				}
			}
		}
	}()

	// src interface was supplied
	// lets lookup the appropriate info
	if vtep.SrcIfName != "" {
		for _, client := range ClientIntf {
			client.GetIntfInfo(vtep.SrcIfName, vtep.intfinfochan)
		}
	} else if vtep.SrcIp.String() != "0.0.0.0" &&
		vtep.SrcIp != nil {
		// SrcIfName is the current vtep
		vtep.Status = VtepStatusNextHopUnknown
		if vtep.DstMac.String() == "" ||
			vtep.DstMac.String() == "00:00:00:00:00:00" {
			// lets try and resolve the mac
			for _, client := range ClientIntf {
				client.GetNextHopInfo(vtep.DstIp, vtep.nexthopchan)
			}
		}
	}
}

func CreateVtep(c *VtepConfig) *VtepDbEntry {

	vtep := saveVtepConfigData(c)

	if _, ok := GetVxlanDB()[vtep.Vni]; ok {
		// lets resolve the mac address
		vtep.VtepFsm()
	} else {
		vtep.Status = VtepStatusDetached
	}

	return vtep
}

func DeProvisionVtep(vtep *VtepDbEntry) {
	// delete vtep resources in hw
	if vtep.Status == VtepStatusUp {
		for _, client := range ClientIntf {
			client.DeleteVtep(vtep)
		}
		if vtep.handle != nil {
			vtep.handle.Close()
		}
	}
	if vtep.Status != VtepStatusDetached {
		vtep.VtepFsmCleanup()
	}

	// clear out the information which was discovered for this VTEP
	vtep.NextHopIp = nil
	if vtep.SrcIfName != "" {
		vtep.SrcIp = nil
	}
	vtep.DstMac, _ = net.ParseMAC("00:00:00:00:00:00")
	vtep.Status = VtepStatusIncomplete
}

func DeleteVtep(c *VtepConfig) {

	key := &VtepDbKey{
		name: c.VtepName,
	}

	vtep := GetVtepDBEntry(key)
	if vtep != nil {
		DeProvisionVtep(vtep)
		delete(vtepDB, *key)
	}
}

func saveVtepConfigData(c *VtepConfig) *VtepDbEntry {
	key := &VtepDbKey{
		name: c.VtepName,
	}
	vtep := GetVtepDBEntry(key)
	if vtep == nil {
		vtep = NewVtepDbEntry(c)
		vtepDB[*key] = vtep
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

// createVtepSenderListener:
// This will listen for packets from the linux stack on the VtepHandleName
// Similarly if the MAC was learned against this VTEP traffic will be transmited
// back to the linux stack from this interface.
func (vtep *VtepDbEntry) createVtepSenderListener() error {

	// TODO need to revisit the timeout interval in case of processing lots of
	// data frames
	handle, err := pcap.OpenLive(vtep.VtepHandleName, 65536, false, 50*time.Millisecond)
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
		//asicDLearnFwdDbEntry(learnmac, vtep.VtepName, vtep.VtepIfIndex)
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
		vxlan.SetVNI(vtep.Vni)

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
