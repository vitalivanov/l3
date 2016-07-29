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
	"l3/ndp/config"
	"l3/ndp/debug"
	"time"
)

/*
 *    Re-Transmit Timer
 */
func (c *NeighborCache) Timer(ifIndex int32, linkIp, nbrIP string, timeValueInMS int, pktCh chan config.PacketData) {
	// Reset the timer if it is already running when we receive Neighbor Solicitation
	if c.RetransTimer != nil {
		c.RetransTimer.Reset(time.Duration(timeValueInMS) * time.Millisecond)
	} else {
		// start the time for the first... provide an after func and move on
		var ReTransmitNeighborSolicitation_func func()
		ReTransmitNeighborSolicitation_func = func() {
			debug.Logger.Info("Timer expired for ifIndex", ifIndex, "IpAddr:", linkIp, "NbrIP:", nbrIP,
				"time to send NeighborSolicitation")
			pktCh <- config.PacketData{linkIp, nbrIP, ifIndex}
		}
		c.RetransTimer = time.AfterFunc(time.Duration(timeValueInMS)*time.Millisecond,
			ReTransmitNeighborSolicitation_func)
	}
}
