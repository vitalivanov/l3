package vxlan

import (
	"net"
)

// interface class is used to store the communication methods
// for the various daemon communications
type VXLANClientIntf interface {
	// used to notify server of updates
	SetServerChannels(s *VxLanConfigChannels)
	ConnectToClients(clientFile string)
	ConstructPortConfigMap()
	// create/delete
	CreateVtep(vtep *VtepDbEntry, vteplistener chan<- string)
	DeleteVtep(vtep *VtepDbEntry)
	CreateVxlan(vxlan *VxlanConfig)
	DeleteVxlan(vxlan *VxlanConfig)
	// access ports
	GetAccessPorts(vlan uint16)
	UpdateAccessPorts()
	CreateAccessPortVlan(vlan uint16, intfList []int)
	DeleteAccessPortVlan(vlan uint16, intfList []int)
	// vtep fsm
	GetIntfInfo(name string, intfchan chan<- VxlanIntfInfo)
	GetNextHopInfo(ip net.IP, nexthopchan chan<- VtepNextHopInfo)
	ResolveNextHopMac(nextHopIp net.IP, nexthopmacchan chan<- net.HardwareAddr)
}

type BaseClientIntf struct {
}

func (b BaseClientIntf) SetServerChannels(s *VxLanConfigChannels) {

}
func (b BaseClientIntf) ConnectToClients(clientFile string) {

}
func (b BaseClientIntf) ConstructPortConfigMap() {

}
func (b BaseClientIntf) GetIntfInfo(name string, intfchan chan<- VxlanIntfInfo) {

}
func (b BaseClientIntf) CreateVtep(vtep *VtepDbEntry) {

}
func (b BaseClientIntf) DeleteVtep(vtep *VtepDbEntry) {

}
func (b BaseClientIntf) CreateVxlan(vxlan *VxlanConfig) {

}
func (b BaseClientIntf) DeleteVxlan(vxlan *VxlanConfig) {

}
func (b BaseClientIntf) CreateVxlanAccess() {

}
func (b BaseClientIntf) DeleteVxlanAccess() {

}
func (b BaseClientIntf) GetAccessPorts(vlan uint16) {

}
func (b BaseClientIntf) UpdateAccessPorts() {

}
func (b BaseClientIntf) CreateAccessPortVlan(vlan uint16, intfList []int) {

}
func (b BaseClientIntf) DeleteAccessPortVlan(vlan uint16, intfList []int) {

}
func (b BaseClientIntf) GetNextHopInfo(ip net.IP, nexthopchan chan<- net.IP) {

}
func (b BaseClientIntf) ResolveNextHopMac(nextHopIp net.IP, nexthopmacchan chan<- net.HardwareAddr) {

}
