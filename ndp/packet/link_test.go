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
package packet

import (
	"net"
	"testing"
)

func dumpLinkInfo(t *testing.T) {
	t.Log(testPktObj.LinkInfo)
}

var nbrIps = []string{
	"2002::2",
	"2002::3",
	"2002::4",
}

func helperForAddingNbr(ip string) {
	for _, nbrIp := range nbrIps {
		addTestNbrEntry(ip, nbrIp)
	}
}

func TestLinkFlushNeighbor(t *testing.T) {
	initTestPacket()
	ipAddr := "2002::1/64"
	testPktObj.InitLink(100, ipAddr, "00:e0:ec:26:a7:ee")
	ip, _, _ := net.ParseCIDR(ipAddr)

	// add neighbors
	helperForAddingNbr(ip.String())

	// flush all neighbor entries
	deleteEntries, err := testPktObj.FlushNeighbors(ipAddr)
	if err != nil {
		t.Error("Failed to flush neighbor cache from packet LinkInfo, error:", err)
	}

	// Validate that deleteEntries has got all the neighbors to be delete
	found := false
	for _, dEntry := range deleteEntries {
		for _, nbrIp := range nbrIps {
			if dEntry == nbrIp {
				found = true
				break
			}
		}
		if !found {
			t.Error("Invalid Delete Entry information", dEntry)

		}
	}

	// Validate that only Nbr's are deleted not the link
	if len(testPktObj.LinkInfo) == 0 {
		t.Error("When flushing neighbors packet linkInfo should not be deleted", testPktObj.LinkInfo)
	}

	// Delete the linkInfo now
	testPktObj.DeleteLink(ipAddr)
	if len(testPktObj.LinkInfo) > 0 {
		t.Error("Failed to delete link")
	}

	// Validate that 0 delete Entries are received
	deleteEntries, err = testPktObj.FlushNeighbors(ipAddr)
	if err == nil {
		t.Error("There is no entry in Neighbor Cache and we still didn't receive error message")
	}
	if len(deleteEntries) > 0 {
		t.Error("There should be zero delete entries")
	}
}

func TestLinkDeleteSingleNbr(t *testing.T) {
	initTestPacket()
	ipAddr := "2002::1/64"
	testPktObj.InitLink(100, ipAddr, "00:e0:ec:26:a7:ee")
	ip, _, _ := net.ParseCIDR(ipAddr)

	// add neighbors
	helperForAddingNbr(ip.String())

	_, err := testPktObj.DeleteNeighbor(ipAddr, nbrIps[1])
	if err == nil {
		t.Error("We should have error out as link address is in CIDR format", ipAddr)
	}

	// delete second neigbor for absolute LocalIP no CIDR format
	deleteEntries, err := testPktObj.DeleteNeighbor(ip.String(), nbrIps[1])
	if err != nil {
		t.Error("Failed to flush neighbor cache from packet LinkInfo, error:", err)
	}

	if len(deleteEntries) != 1 {
		t.Error("Delete Single Neighbor should have returned only 1 entry for delete",
			"RCVD DELETE ENTRIES ARE:", deleteEntries)
	}
	// Validate that deleteEntries has got all the neighbors to be delete
	found := false
	for _, dEntry := range deleteEntries {
		for _, nbrIp := range nbrIps {
			if dEntry == nbrIp {
				found = true
				break
			}
		}
		if !found {
			t.Error("Invalid Delete Entry information", dEntry)

		}
	}

	// AFTER SINGLE ENTRY VERIFY LINKINFO is not 0 and then flush all neighbors

	// Validate that only Nbr's are deleted not the link
	if len(testPktObj.LinkInfo) == 0 {
		t.Error("When flushing neighbors packet linkInfo should not be deleted", testPktObj.LinkInfo)
	}

	// Delete the linkInfo now
	testPktObj.DeleteLink(ipAddr)
	if len(testPktObj.LinkInfo) > 0 {
		t.Error("Failed to delete link")
	}

	// Validate that 0 delete Entries are received
	deleteEntries, err = testPktObj.FlushNeighbors(ipAddr)
	if err == nil {
		t.Error("There is no entry in Neighbor Cache and we still didn't receive error message")
	}
	if len(deleteEntries) > 0 {
		t.Error("There should be zero delete entries")
	}
}
