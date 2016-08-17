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
	"math/rand"
	"time"
)

/*
 * Delay first probe timer handler
 */
func (c *NeighborCache) DelayProbe() {
	if c.DelayFirstProbeTimer != nil {
		// we should never come here
		debug.Logger.Debug("Resetting delay probe timer for ifIndex:", c.MyLinkInfo.IfIndex, "linkIp:", c.MyLinkInfo.IpAddr,
			"nbrIp:", c.IpAddr)
		c.DelayFirstProbeTimer.Reset(time.Duration(DELAY_FIRST_PROBE_TIME) * time.Second)
	} else {
		var DelayProbeExpired_func func()
		DelayProbeExpired_func = func() {
			debug.Logger.Debug("Delay Probe Timer Expired for ifIndex:", c.MyLinkInfo.IfIndex, "linkIp:",
				c.MyLinkInfo.IpAddr, "nbrIp:", c.IpAddr, "Sending Probe NS msgs")
			c.MyLinkInfo.ReturnCh <- config.PacketData{c.MyLinkInfo.IpAddr, c.IpAddr, c.MyLinkInfo.IfIndex}
		}
		debug.Logger.Debug("Setting Delay Probe timer for ifIndex:", c.MyLinkInfo.IfIndex, "linkIp:", c.MyLinkInfo.IpAddr,
			"nbrIp:", c.IpAddr)
		c.DelayFirstProbeTimer = time.AfterFunc(time.Duration(DELAY_FIRST_PROBE_TIME)*time.Second,
			DelayProbeExpired_func)
	}
}

/*
 *    Re-Transmit Timer
 */
func (c *NeighborCache) Timer() {
	// Reset the timer if it is already running when we receive Neighbor Advertisment..
	if c.RetransTimer != nil {
		debug.Logger.Debug("Resetting Re-Transmit timer for ifIndex:", c.MyLinkInfo.IfIndex, "linkIp:", c.MyLinkInfo.IpAddr,
			"nbrIp:", c.IpAddr)
		c.RetransTimer.Reset(time.Duration(c.RetransTimerConfig) * time.Millisecond)
	} else {
		// start the time for the first... provide an after func and move on
		var ReTransmitNeighborSolicitation_func func()
		ReTransmitNeighborSolicitation_func = func() {
			debug.Logger.Debug("Re-Transmit Timer Expired for ifIndex:", c.MyLinkInfo.IfIndex, "linkIp:",
				c.MyLinkInfo.IpAddr, "nbrIp:", c.IpAddr, "Sending Neighbor Solicitation")
			c.MyLinkInfo.ReturnCh <- config.PacketData{c.MyLinkInfo.IpAddr, c.IpAddr, c.MyLinkInfo.IfIndex}
			// set timer to NIL so after sending a packet... we can re-start the timer
			//c.RetransTimer = nil
			// RetransTimer will be stopped by Reachability Timer when an Advertisement is rcvd
			// After sending packet then only Re-Transmit Timer will be re-started
			//c.RetransTimer.Reset(time.Duration(c.RetransTimerConfig) * time.Millisecond)
		}
		debug.Logger.Debug("Setting Re-Transmit timer for ifIndex:", c.MyLinkInfo.IfIndex, "linkIp:", c.MyLinkInfo.IpAddr,
			"nbrIp:", c.IpAddr)
		c.RetransTimer = time.AfterFunc(time.Duration(c.RetransTimerConfig)*time.Millisecond,
			ReTransmitNeighborSolicitation_func)
	}
}

/*
 *  Start Reachable Timer
 */
func (c *NeighborCache) RchTimer() {
	// When reachable timer is running or updated we need to stop delay probe timer and re-transmit timer
	// no matter what happens
	c.StopDelayProbeTimer()
	c.StopReTransmitTimer()
	if c.ReachableTimer != nil {
		// if Re-Transmit Timer is still running then stop it, this is now taken care of by UpdateProbe
		//c.StopReTransmitTimer()
		debug.Logger.Debug("Re-Setting Reachable Timer for neighbor:", c.IpAddr, "for my Link:", *c.MyLinkInfo)
		//Reset the timer as we have received an advertisment for the neighbor
		c.ReachableTimer.Reset(time.Duration(c.BaseReachableTimer) * time.Millisecond)
	} else {
		// This is first time initialization of reachable timer... let set it up
		var ReachableTimer_func func()
		ReachableTimer_func = func() {
			debug.Logger.Debug("Reachable Timer expired for neighbor:", c.IpAddr, "initiating unicast NS",
				"for my Link:", *c.MyLinkInfo)
			c.MyLinkInfo.ReturnCh <- config.PacketData{c.MyLinkInfo.IpAddr, c.IpAddr, c.MyLinkInfo.IfIndex}
			//c.Timer()
			// also re-setting the reachable timer..
			//c.ReachableTimer.Reset(time.Duration(c.BaseReachableTimer) * time.Millisecond)
		}
		debug.Logger.Debug("Setting Reachable Timer for neighbor:", c.IpAddr, "for my Link:", *c.MyLinkInfo)
		c.ReachableTimer = time.AfterFunc(time.Duration(c.BaseReachableTimer)*time.Millisecond,
			ReachableTimer_func)
	}
}

/*
 *  Helper function to randomize BASE_REACHABLE_TIME
 */
func computeBase(reachableTime uint32) float32 {
	return float32(reachableTime) + ((rand.Float32() * MIN_RANDOM_FACTOR) + MIN_RANDOM_FACTOR)
}

/*
 *  Re-computing base reachable timer
 */
func (c *NeighborCache) ReComputeBaseReachableTimer() {
	if c.RecomputeBaseTimer != nil {
		// We need to recompute this timer on RA packets
	} else {
		// set go after function to recompute the time and also restart the timer after that
		var RecomputeBaseTimer_func func()
		RecomputeBaseTimer_func = func() {
			c.BaseReachableTimer = computeBase(c.ReachableTimeConfig)
			c.ReachableTimer.Reset(time.Duration(c.BaseReachableTimer) * time.Millisecond)
		}
		debug.Logger.Debug("Setting Recompute Timer for neighbor:", c.IpAddr, "for my Link:", *c.MyLinkInfo)
		c.RecomputeBaseTimer = time.AfterFunc(time.Duration(RECOMPUTE_BASE_REACHABLE_TIMER)*time.Hour,
			RecomputeBaseTimer_func)
	}
}

/*
 *  Stop ReTransmit Timer
 */
func (c *NeighborCache) StopReTransmitTimer() {
	if c.RetransTimer != nil {
		debug.Logger.Debug("Stopping re-transmit timer for Neighbor", c.IpAddr)
		c.RetransTimer.Stop()
		c.RetransTimer = nil
	}
}

/*
 *  Stop Reachable Timer
 */
func (c *NeighborCache) StopReachableTimer() {
	if c.ReachableTimer != nil {
		debug.Logger.Debug("Stopping reachable timer for Neighbor", c.IpAddr)
		c.ReachableTimer.Stop()
		c.ReachableTimer = nil
	}
}

/*
 *  Stop Reachable Timer
 */
func (c *NeighborCache) StopReComputeBaseTimer() {
	if c.RecomputeBaseTimer != nil {
		debug.Logger.Debug("Stopping re-compute timer for Neighbor", c.IpAddr)
		c.RecomputeBaseTimer.Stop()
		c.RecomputeBaseTimer = nil
	}
}

/*
 *  stop delay probe Timer
 */
func (c *NeighborCache) StopDelayProbeTimer() {
	if c.DelayFirstProbeTimer != nil {
		debug.Logger.Debug("Stopping DelayFirstProbeTimer for Neighbor", c.IpAddr)
		c.DelayFirstProbeTimer.Stop()
		c.DelayFirstProbeTimer = nil
	}
}

/*
 *  Update Probe Information
 *	1) Stop Delay Timer if running
 *	2) Stop Re-Transmit Timer if running
 *	3) Update Probes Sent counter to 0
 */
func (c *NeighborCache) UpdateProbe() {
	c.StopDelayProbeTimer()
	c.StopReTransmitTimer()
	c.ProbesSent = uint8(0)
}

/*
 *  Initialize cache with default values..
 */
func (c *NeighborCache) InitCache(reachableTime, retransTime uint32, myIp, myLinkip string, myLinkIfIndex int32,
	myLinkRevCh chan config.PacketData) {
	c.ReachableTimeConfig = reachableTime
	c.RetransTimerConfig = retransTime
	c.BaseReachableTimer = computeBase(reachableTime)
	c.State = INCOMPLETE
	c.IpAddr = myIp
	c.MyLinkInfo = &ParentLinkInfo{
		IfIndex:  myLinkIfIndex,
		IpAddr:   myLinkip,
		ReturnCh: myLinkRevCh,
	}
	// Once initalized start reachable timer... And also start one hour timer for re-computing BaseReachableTimer
	c.RchTimer()
	c.ReComputeBaseReachableTimer()
}

/*
 *  Delete Cache completely
 */
func (c *NeighborCache) DeInitCache() {
	// stopping all three timers in accending order
	c.StopReTransmitTimer()
	c.StopReachableTimer()
	c.StopReComputeBaseTimer()
	c.StopDelayProbeTimer()
	// deleting link information
	c.MyLinkInfo = nil
}
