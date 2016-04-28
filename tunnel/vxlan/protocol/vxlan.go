// vxlandb.go
package vxlan

import (
	"net"
)

// vni -> db entry
var vxlanDB map[uint32]*vxlanDbEntry

type vxlanDbEntry struct {
	VNI         uint32
	VlanId      uint16 // used to tag inner ethernet frame when egressing
	Group       net.IP // multicast group IP
	MTU         uint32 // MTU size for each VTEP
	VtepMembers []uint32
}

// vlan -> vni
var vxlanVlanToVniDb map[uint16]uint32

func NewVxlanDbEntry(c *VxlanConfig) *vxlanDbEntry {
	return &vxlanDbEntry{
		VNI:         c.VNI,
		VlanId:      c.VlanId,
		Group:       c.Group,
		MTU:         c.MTU,
		VtepMembers: make([]uint32, 0),
	}
}

func GetVxlanDB() map[uint32]*vxlanDbEntry {
	return vxlanDB
}

func saveVxLanConfigData(c *VxlanConfig) {
	if _, ok := vxlanDB[c.VNI]; !ok {
		vxlan := NewVxlanDbEntry(c)
		vxlanDB[c.VNI] = vxlan
		vxlanVlanToVniDb[c.VlanId] = c.VNI
	}
}

// DeleteVxLAN:
// Configuration interface for creating the vlxlan instance
func CreateVxLAN(c *VxlanConfig) {
	saveVxLanConfigData(c)

	for _, client := range ClientIntf {
		// create vxlan resources in hw
		client.CreateVxlan(c)
	}

	// lets find all the vteps which are in VtepStatusConfigPending state
	// and initiate a hwConfig
	for _, vtep := range GetVtepDB() {
		if vtep.Status == VtepStatusIncompletNoAssociation {
			// start the fsm for the vtep
			vtep.VtepFsm()
		}
	}
}

// DeleteVxLAN:
// Configuration interface for deleting the vlxlan instance
func DeleteVxLAN(c *VxlanConfig) {

	// delete vxlan resources in hw
	for _, client := range ClientIntf {
		client.DeleteVxlan(c)
	}

	delete(vxlanDB, c.VNI)

}
