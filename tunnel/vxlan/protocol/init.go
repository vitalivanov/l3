// init.go
package vxlan

import ()

func init() {
	// initialize the various db maps
	vtepDB = make(map[VtepDbKey]*VtepDbEntry, 0)
	vxlanDB = make(map[uint32]*vxlanDbEntry, 0)
	vxlanVlanToVniDb = make(map[uint16]uint32, 0)

	PortConfigMap = make(map[int32]portConfig, 0)
	portDB = make(map[string]*VxlanPort, 0)

}
