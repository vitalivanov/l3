//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
// _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//

/*
Ospf_packet.go
*/
package server

import (
	//  "encoding/hex"
	"fmt"
	//	"l3/ospf/config"
	//"net"
	"testing"
	//	"utils/logging"
)

func TestOSPFDBDecode(t *testing.T) {
	data := []byte{0xc2, 0x03, 0x56, 0xcc, 0x00, 0x01, 0xc2, 0x00, 0x56, 0xab, 0x00, 0x00, 0x08, 0x00, 0x45, 0xc0, 0x00, 0x40, 0x00, 0x7b, 0x00, 0x00, 0x01, 0x59, 0x7c, 0x28, 0x0a, 0x00, 0x14, 0x02, 0x0a, 0x00, 0x14, 0x01, 0x02, 0x02, 0x00, 0x20, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x14, 0x87, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x52, 0x07, 0x00, 0x00, 0x14, 0x92, 0xff, 0xf6, 0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01}
	data_less_len := []byte{0xc2, 0x03, 0x56, 0xcc, 0x00, 0x01, 0xc2, 0x00, 0x56, 0xab, 0x00, 0x00, 0x08, 0x00, 0x45, 0xc0, 0x00, 0x40, 0x00, 0x7b, 0x00, 0x00, 0x01, 0x59, 0x7c, 0x28, 0x0a, 0x00, 0x14, 0x02, 0x0a, 0x00, 0x14, 0x01, 0x02, 0x02, 0x00, 0x20, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x14, 0x87, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x52, 0x07, 0x00, 0x00, 0x14, 0x92, 0xff, 0xf6, 0x00, 0x03, 0x00, 0x01, 0x00}

	ospfdbd_data := NewOspfDatabaseDescriptionData()
	ospfdbd_data.lsa_headers = []ospfLSAHeader{}
	pktlen := uint16(len(data))

	fmt.Printf("Decode DB: 1)Standard db description ")
	DecodeDatabaseDescriptionData(data, ospfdbd_data, pktlen)
	fmt.Printf("Decode DB: Success")
	fmt.Printf("Decode DB: 2) Min pkt length check ")
	pktlen = uint16(len(data_less_len))
	DecodeDatabaseDescriptionData(data_less_len, ospfdbd_data, pktlen)
	fmt.Printf("Decode DB: Success")
	dbdNbrMsg := ospfNeighborDBDMsg{
		ospfNbrConfKey: NeighborConfKey{
			IPAddr:  "20.0.0.1",
			IntfIdx: 1,
		},
		ospfNbrDBDData: *ospfdbd_data,
	}
	fmt.Println("\n Get Server object")
	server := getServerObject()
	go startDummyChannels(server)
	if server != nil {
		fmt.Printf("Send message to neighbor data")
		server.neighborDBDEventCh <- dbdNbrMsg
	}

}
