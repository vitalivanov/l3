package server

import (
	"asicd/asicdConstDefs"
	"asicdServices"
	"encoding/json"
	"fmt"
	nanomsg "github.com/op/go-nanomsg"
	"utils/commonDefs"
)

type AsicdClient struct {
	OspfClientBase
	ClientHdl *asicdServices.ASICDServicesClient
}

func (server *OSPFServer) createASICdSubscriber() {
	for {
		server.logger.Info("Read on ASICd subscriber socket...")
		asicdrxBuf, err := server.asicdSubSocket.Recv(0)
		if err != nil {
			server.logger.Err(fmt.Sprintln("Recv on ASICd subscriber socket failed with error:", err))
			server.asicdSubSocketErrCh <- err
			continue
		}
		server.logger.Info(fmt.Sprintln("ASIC subscriber recv returned:", asicdrxBuf))
		server.asicdSubSocketCh <- asicdrxBuf
	}
}

func (server *OSPFServer) listenForASICdUpdates(address string) error {
	var err error
	if server.asicdSubSocket, err = nanomsg.NewSubSocket(); err != nil {
		server.logger.Err(fmt.Sprintln("Failed to create ASICd subscribe socket, error:", err))
		return err
	}

	if err = server.asicdSubSocket.Subscribe(""); err != nil {
		server.logger.Err(fmt.Sprintln("Failed to subscribe to \"\" on ASICd subscribe socket, error:", err))
		return err
	}

	if _, err = server.asicdSubSocket.Connect(address); err != nil {
		server.logger.Err(fmt.Sprintln("Failed to connect to ASICd publisher socket, address:", address, "error:", err))
		return err
	}

	server.logger.Info(fmt.Sprintln("Connected to ASICd publisher at address:", address))
	if err = server.asicdSubSocket.SetRecvBuffer(1024 * 1024); err != nil {
		server.logger.Err(fmt.Sprintln("Failed to set the buffer size for ASICd publisher socket, error:", err))
		return err
	}
	return nil
}

func (server *OSPFServer) processAsicdNotification(asicdrxBuf []byte) {
	var msg asicdConstDefs.AsicdNotification
	err := json.Unmarshal(asicdrxBuf, &msg)
	if err != nil {
		server.logger.Err(fmt.Sprintln("Unable to unmarshal asicdrxBuf:", asicdrxBuf))
		return
	}
	if msg.MsgType == asicdConstDefs.NOTIFY_IPV4INTF_CREATE ||
		msg.MsgType == asicdConstDefs.NOTIFY_IPV4INTF_DELETE {
		var NewIpv4IntfMsg asicdConstDefs.IPv4IntfNotifyMsg
		var ipv4IntfMsg IPv4IntfNotifyMsg
		err = json.Unmarshal(msg.Msg, &NewIpv4IntfMsg)
		if err != nil {
			server.logger.Err(fmt.Sprintln("Unable to unmarshal msg:", msg.Msg))
			return
		}
		ipv4IntfMsg.IpAddr = NewIpv4IntfMsg.IpAddr
		ipv4IntfMsg.IfType = uint8(asicdConstDefs.GetIntfTypeFromIfIndex(NewIpv4IntfMsg.IfIndex))
		ipv4IntfMsg.IfId = uint16(asicdConstDefs.GetIntfIdFromIfIndex(NewIpv4IntfMsg.IfIndex))
		if msg.MsgType == asicdConstDefs.NOTIFY_IPV4INTF_CREATE {
			server.logger.Info(fmt.Sprintln("Receive IPV4INTF_CREATE", ipv4IntfMsg))
			server.createIPIntfConfMap(ipv4IntfMsg)
			if ipv4IntfMsg.IfType == commonDefs.L2RefTypePort { // PHY
				server.updateIpInPortPropertyMap(ipv4IntfMsg, msg.MsgType)
			} else if ipv4IntfMsg.IfType == commonDefs.L2RefTypeVlan { // Vlan
				server.updateIpInVlanPropertyMap(ipv4IntfMsg, msg.MsgType)
			}
		} else {
			server.logger.Info(fmt.Sprintln("Receive IPV4INTF_DELETE", ipv4IntfMsg))
			server.deleteIPIntfConfMap(ipv4IntfMsg)
			if ipv4IntfMsg.IfType == commonDefs.L2RefTypePort { // PHY
				server.updateIpInPortPropertyMap(ipv4IntfMsg, msg.MsgType)
			} else if ipv4IntfMsg.IfType == commonDefs.L2RefTypeVlan { // Vlan
				server.updateIpInVlanPropertyMap(ipv4IntfMsg, msg.MsgType)
			}
		}
	} else if msg.MsgType == asicdConstDefs.NOTIFY_VLAN_CREATE ||
		msg.MsgType == asicdConstDefs.NOTIFY_VLAN_DELETE {
		//Vlan Create Msg
		var vlanNotifyMsg asicdConstDefs.VlanNotifyMsg
		err = json.Unmarshal(msg.Msg, &vlanNotifyMsg)
		if err != nil {
			server.logger.Err(fmt.Sprintln("Unable to unmashal vlanNotifyMsg:", msg.Msg))
			return
		}
		server.updatePortPropertyMap(vlanNotifyMsg, msg.MsgType)
		server.updateVlanPropertyMap(vlanNotifyMsg, msg.MsgType)
	}
}
