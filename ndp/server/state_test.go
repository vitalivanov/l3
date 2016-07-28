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
package server

import (
	"l3/ndp/config"
	"reflect"
	"testing"
)

var nbr []config.NeighborInfo

func populateNbrInfoTest(svr *NDPServer) {
	nbr1 := config.NeighborInfo{
		IpAddr:      "2002::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::1/64",
		MacAddr:     "aa:bb:cc:dd:ee:01",
	}
	nbr2 := config.NeighborInfo{
		IpAddr:      "2003::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::2/64",
		MacAddr:     "aa:bb:cc:dd:ee:02",
	}
	nbr3 := config.NeighborInfo{
		IpAddr:      "2004::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::3/64",
		MacAddr:     "aa:bb:cc:dd:ee:03",
	}
	nbr4 := config.NeighborInfo{
		IpAddr:      "2005::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::4/64",
		MacAddr:     "aa:bb:cc:dd:ee:04",
	}
	nbr5 := config.NeighborInfo{
		IpAddr:      "2006::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::5/64",
		MacAddr:     "aa:bb:cc:dd:ee:05",
	}
	nbr = append(nbr, nbr1)
	nbr = append(nbr, nbr2)
	nbr = append(nbr, nbr3)
	nbr = append(nbr, nbr4)
	nbr = append(nbr, nbr5)
	for i := 0; i < TEST_NBR_ENTRIES; i++ {
		svr.insertNeigborInfo(&nbr[i])
	}
}

func TestGetAllNbrEntries(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	populateNbrInfoTest(svr)
	if len(svr.NeighborInfo) < TEST_NBR_ENTRIES || len(svr.neighborKey) < TEST_NBR_ENTRIES {
		t.Error("Inserting neighbor entries failed")
	}
	nextIdx, count, runTimeEntries := svr.GetNeighborEntries(0, TEST_NBR_ENTRIES)
	if nextIdx != 0 {
		t.Error("Not All Entries are fetched, nextIdx is", nextIdx)
	}
	if count != TEST_NBR_ENTRIES {
		t.Error("Not all entries are found from runtime, count is", count)
	}
	if !reflect.DeepEqual(nbr, runTimeEntries) {
		t.Error("Get All Entries Failed, nbr Info Stored:", nbr, "Runtime Entries fetched:", runTimeEntries)
	}
	svr.DeInitGlobalDS()
}

func TestGet3NbrEntries(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	populateNbrInfoTest(svr)
	if len(svr.NeighborInfo) < TEST_NBR_ENTRIES || len(svr.neighborKey) < TEST_NBR_ENTRIES {
		t.Error("Inserting neighbor entries failed")
	}
	nextIdx, count, runTimeEntries := svr.GetNeighborEntries(2, TEST_NBR_ENTRIES)
	if nextIdx != 0 {
		t.Error("Not All Entries are fetched, nextIdx is", nextIdx)
	}
	if count != TEST_NBR_ENTRIES-2 {
		t.Error("Not all entries are found from runtime, count is", count)
	}

	if len(runTimeEntries) == TEST_NBR_ENTRIES {
		t.Error("Len of fetched entries should be", count, " but got", len(runTimeEntries))
	}
	for i := 2; i < count; i++ {
		if !reflect.DeepEqual(nbr[i], runTimeEntries[i-2]) {
			t.Error("Get All Entries Failed, nbr Info Stored:", nbr[i], "Runtime Entries fetched:", runTimeEntries[i-2])
		}
	}
	svr.DeInitGlobalDS()
}

func TestGetNbrEntriesNilEntry(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	nextIdx, count, runTimeEntries := svr.GetNeighborEntries(0, TEST_NBR_ENTRIES)
	if nextIdx != 0 || count != 0 || runTimeEntries != nil {
		t.Error("Failed to return 0 entries")
	}
	svr.DeInitGlobalDS()
}

func TestGetNbrEntry(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	nbrEntry := svr.GetNeighborEntry("2002::1/64")
	if nbrEntry != nil {
		t.Error("there is no entry in the database and we received nbr info", nbrEntry)
	}
	populateNbrInfoTest(svr)
	nbrEntry = svr.GetNeighborEntry("2002::1/64")
	if !reflect.DeepEqual(*nbrEntry, nbr[0]) {
		t.Error("Get Entry for ipAddr 2002::1/64 failed", "received info", nbrEntry, "strore info", nbr[0])
	}
	svr.DeInitGlobalDS()
}
