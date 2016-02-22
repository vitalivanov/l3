package server

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"l3/ospf/config"
	"net"
	"time"
)

/*
LSA request
 0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Version #   |       3       |         Packet length         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Router ID                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Area ID                             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Checksum            |             AuType            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Authentication                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Authentication                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          LS type                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Link State ID                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     Advertising Router                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                              ...                              |
*/
type ospfLSAReq struct {
	ls_type       uint32
	link_state_id uint32
	adv_router_id uint32
}

type ospfNeighborLSAreqMsg struct {
	lsa_slice []ospfLSAReq
	nbrKey    uint32
}

type ospfNeighborLSDBMsg struct {
	areaId uint32
	data   []byte
}

type ospfNeighborLSAACKMsg struct {
	lsa_headers []ospfLSAHeader
	nbrId       uint32
}

func NewospfNeighborLSDBMsg() *ospfNeighborLSDBMsg {
	return &ospfNeighborLSDBMsg{}
}

func newospfNeighborLSAACKMsg() *ospfNeighborLSAACKMsg {
	return &ospfNeighborLSAACKMsg{}
}

type ospfNeighborLSAUpdMsg struct {
	nbrKey uint32
	data   []byte
	areaId uint32
}

type ospfNeighborLSAUpdPkt struct {
	no_lsas uint32
	lsa     []byte
}

func newospfNeighborLSAUpdPkt() *ospfNeighborLSAUpdPkt {
	return &ospfNeighborLSAUpdPkt{}
}

func encodeLSAReqPkt(lsa_data []ospfLSAReq) []byte {
	pkt := make([]byte, len(lsa_data)*3*8)
	for i := 0; i < len(lsa_data); i++ {
		binary.BigEndian.PutUint32(pkt[i:i+4], lsa_data[i].ls_type)
		binary.BigEndian.PutUint32(pkt[i:i+4], lsa_data[i].link_state_id)
		binary.BigEndian.PutUint32(pkt[i:i+4], lsa_data[i].adv_router_id)
	}
	return pkt
}

func decodeLSAReq(data []byte) (lsa_req ospfLSAReq) {
	lsa_req.ls_type = binary.BigEndian.Uint32(data[0:4])
	lsa_req.link_state_id = binary.BigEndian.Uint32(data[4:8])
	lsa_req.adv_router_id = binary.BigEndian.Uint32(data[8:12])
	return lsa_req
}

func decodeLSAReqPkt(data []byte, pktlen uint16) []ospfLSAReq {
	no_of_lsa := int(pktlen / 3)
	lsa_req_pkt := []ospfLSAReq{}
	for i := 0; i < no_of_lsa; i++ {
		lsa_req := decodeLSAReq(data[i : i+3])
		lsa_req_pkt = append(lsa_req_pkt, lsa_req)
	}
	return lsa_req_pkt
}

func (server *OSPFServer) BuildLSAReqPkt(intfKey IntfConfKey, ent IntfConf,
	nbrConf OspfNeighborEntry, lsa_req_pkt []ospfLSAReq, dstMAC net.HardwareAddr) (data []byte) {
	ospfHdr := OSPFHeader{
		ver:      OSPF_VERSION_2,
		pktType:  uint8(DBDescriptionType),
		pktlen:   0,
		routerId: server.ospfGlobalConf.RouterId,
		areaId:   ent.IfAreaId,
		chksum:   0,
		authType: ent.IfAuthType,
		//authKey:        ent.IfAuthKey,
	}

	ospfPktlen := OSPF_HEADER_SIZE
	ospfPktlen = ospfPktlen + len(lsa_req_pkt)

	ospfHdr.pktlen = uint16(ospfPktlen)

	ospfEncHdr := encodeOspfHdr(ospfHdr)
	server.logger.Info(fmt.Sprintln("ospfEncHdr:", ospfEncHdr))
	lsaDataEnc := encodeLSAReqPkt(lsa_req_pkt)
	server.logger.Info(fmt.Sprintln("lsa Pkt:", lsaDataEnc))

	ospf := append(ospfEncHdr, lsaDataEnc...)
	server.logger.Info(fmt.Sprintln("OSPF LSA REQ:", ospf))
	csum := computeCheckSum(ospf)
	binary.BigEndian.PutUint16(ospf[12:14], csum)
	copy(ospf[16:24], ent.IfAuthKey)

	ipPktlen := IP_HEADER_MIN_LEN + ospfHdr.pktlen
	ipLayer := layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(IP_HEADER_MIN_LEN),
		TOS:      uint8(0xc0),
		Length:   uint16(ipPktlen),
		TTL:      uint8(1),
		Protocol: layers.IPProtocol(OSPF_PROTO_ID),
		SrcIP:    ent.IfIpAddr,
		DstIP:    nbrConf.OspfNbrIPAddr,
	}

	ethLayer := layers.Ethernet{
		SrcMAC:       ent.IfMacAddr,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, &ethLayer, &ipLayer, gopacket.Payload(ospf))
	lsaPkt := buffer.Bytes()
	server.logger.Info(fmt.Sprintln("lsaPkt: ", lsaPkt))

	return lsaPkt

}

func (server *OSPFServer) BuildAndSendLSAReq(nbrId uint32, nbrConf OspfNeighborEntry) (curr_index uint8) {
	/* calculate max no of requests that can be added
	for req packet */

	var add_items uint8
	var lsa_req []ospfLSAReq
	lsa_req = []ospfLSAReq{}
	var req ospfLSAReq
	var i uint8
	reqlist := ospfNeighborRequest_list[nbrId]
	req_list_items := uint8(len(reqlist)) - nbrConf.ospfNbrLsaReqIndex
	max_req := calculateMaxLsaReq()
	if max_req > req_list_items {
		add_items = req_list_items
		nbrConf.ospfNbrLsaReqIndex = uint8(len(reqlist))

	} else {
		add_items = uint8(max_req)
		nbrConf.ospfNbrLsaReqIndex += max_req
	}
	index := nbrConf.ospfNbrLsaReqIndex
	for i = 0; i < add_items; i++ {
		req.ls_type = uint32(reqlist[i].lsa_headers.ls_type)
		req.link_state_id = reqlist[i].lsa_headers.link_state_id
		req.adv_router_id = reqlist[i].lsa_headers.adv_router_id
		nbrConf.req_list_mutex.Lock()
		lsa_req = append(lsa_req, req)
		nbrConf.req_list_mutex.Unlock()
		/* update LSA Retx list */
		reTxNbr := newospfNeighborRetx()
		reTxNbr.lsa_headers = reqlist[i].lsa_headers
		reTxNbr.valid = true
		nbrConf.retx_list_mutex.Lock()
		reTxList := ospfNeighborRetx_list[nbrId]
		reTxList = append(reTxList, reTxNbr)
		nbrConf.retx_list_mutex.Unlock()

	}
	server.logger.Info(fmt.Sprintln("LSA request: total requests out, req_list_len, current req_list_index ", add_items, len(reqlist), nbrConf.ospfNbrLsaReqIndex))
	server.logger.Info(fmt.Sprintln("LSA request: lsa_req", lsa_req))

	nbrConf.ospfNbrLsaSendCh <- lsa_req
	index += add_items
	return index
}

/*
LSA update packet
   0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Version #   |       4       | d        Packet length         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Router ID                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Area ID                             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Checksum            |             AuType            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Authentication                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Authentication                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                            # LSAs                             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +-                                                            +-+
       |                             LSAs                              |
       +-                                                            +-+
       |                              ...                              |
*/

func (server *OSPFServer) BuildLsaUpdPkt(intfKey IntfConfKey, ent IntfConf,
	nbrConf OspfNeighborEntry, dstMAC net.HardwareAddr, dstIp net.IP, lsa_pkt_size int, lsaUpdEnc []byte) (data []byte) {
	ospfHdr := OSPFHeader{
		ver:      OSPF_VERSION_2,
		pktType:  uint8(LSUpdateType),
		pktlen:   0,
		routerId: server.ospfGlobalConf.RouterId,
		areaId:   ent.IfAreaId,
		chksum:   0,
		authType: ent.IfAuthType,
		//authKey:        ent.IfAuthKey,
	}

	ospfPktlen := OSPF_HEADER_SIZE
	//lsa_header_size := OSPF_LSA_HEADER_SIZE
	ospfPktlen = ospfPktlen + lsa_pkt_size

	ospfHdr.pktlen = uint16(ospfPktlen)

	ospfEncHdr := encodeOspfHdr(ospfHdr)
	server.logger.Info(fmt.Sprintln("ospfEncHdr:", ospfEncHdr))

	server.logger.Info(fmt.Sprintln("LSA upd Pkt:", lsaUpdEnc))

	ospf := append(ospfEncHdr, lsaUpdEnc...)
	server.logger.Info(fmt.Sprintln("OSPF LSA UPD:", ospf))
	csum := computeCheckSum(ospf)
	binary.BigEndian.PutUint16(ospf[12:14], csum)
	copy(ospf[16:24], ent.IfAuthKey)

	ipPktlen := IP_HEADER_MIN_LEN + ospfHdr.pktlen
	ipLayer := layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(IP_HEADER_MIN_LEN),
		TOS:      uint8(0xc0),
		Length:   uint16(ipPktlen),
		TTL:      uint8(1),
		Protocol: layers.IPProtocol(OSPF_PROTO_ID),
		SrcIP:    ent.IfIpAddr,
		DstIP:    dstIp, //net.IP{40, 1, 1, 2},
	}

	ethLayer := layers.Ethernet{
		SrcMAC:       ent.IfMacAddr,
		DstMAC:       dstMAC, //net.HardwareAddr{0x00, 0xe0, 0x4c, 0x68, 0x00, 0x81},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, &ethLayer, &ipLayer, gopacket.Payload(ospf))
	server.logger.Info(fmt.Sprintln("buffer: ", buffer))
	lsaUpd := buffer.Bytes()
	server.logger.Info(fmt.Sprintln("flood Pkt: ", lsaUpd))

	return lsaUpd

}

func (server *OSPFServer) ProcessLsaUpdPkt(data []byte, ospfHdrMd *OspfHdrMetadata,
	ipHdrMd *IpHdrMetadata, key IntfConfKey) error {

	routerId := convertIPv4ToUint32(ospfHdrMd.routerId)

	msg := ospfNeighborLSAUpdMsg{
		nbrKey: routerId,
		areaId: ospfHdrMd.areaId,
		data:   data,
	}

	server.neighborLSAUpdEventCh <- msg
	/*  call lsdb API */
	server.logger.Info(fmt.Sprintln("LSA update: Received LSA update with router_id , lentgh ", routerId, ospfHdrMd.pktlen))
	server.logger.Info(fmt.Sprintln("LSA update: pkt byte[]: ", data))
	return nil
}

/*
@fn processLSAUpdEvent
 Get total lsas. Update LSDB for each LSA
*/

func (server *OSPFServer) processLSAUpdEvent(msg ospfNeighborLSAUpdMsg) {
	nbr, exists := server.NeighborConfigMap[msg.nbrKey]
	if !exists {
		return
	}

	discard := server.lsaUpdDiscardCheck(nbr)
	if discard {
		return
	}

	no_lsa := binary.BigEndian.Uint32(msg.data[0:4])
	server.logger.Info(fmt.Sprintln("LSAUPD: Nbr, No of LSAs ", msg.nbrKey, no_lsa, "  len  ", len(msg.data)))
	lsa_header := NewLsaHeader()
	/* decode each LSA and send to lsdb
	 */
	index := 4
	end_index := 0
	for i := 0; i < int(no_lsa); i++ {
		decodeLsaHeader(msg.data[index:index+OSPF_LSA_HEADER_SIZE], lsa_header)
		server.logger.Info(fmt.Sprintln("LSAUPD: lsaheader decoded adv_rter ", lsa_header.Adv_router,
			" linkid ", lsa_header.LinkId, " lsage ", lsa_header.LSAge,
			" checksum ", lsa_header.LSChecksum, " seq num ", lsa_header.LSSequenceNum,
			" LSTYPE ", lsa_header.LSType,
			" len ", lsa_header.length))
		end_index = int(lsa_header.length) + index /* length includes data + header */
		/* send message to lsdb */
		lsdb_msg := NewLsdbUpdateMsg()
		lsdb_msg.AreaId = msg.areaId
		lsdb_msg.MsgType = LsdbAdd /* TODO Correct the message type */
		lsdb_msg.Data = make([]byte, end_index-i)
		server.logger.Info(fmt.Sprintln("LSAUPD: send to lsdb. lsa ", i, " start ", index, " end ", end_index))
		copy(lsdb_msg.Data, msg.data[index:end_index])
		index = end_index
		server.LsdbUpdateCh <- *lsdb_msg
	}
}

/* link state ACK packet
0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Version #   |       5       |         Packet length         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Router ID                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                           Area ID                             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Checksum            |             AuType            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Authentication                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Authentication                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +-                                                             -+
      |                             A                                 |
      +-                 Link State Advertisement                    -+
      |                           Header                              |
      +-                                                             -+
      |                                                               |
      +-                                                             -+
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                              ...                              |
*/
func (server *OSPFServer) ProcessLSAAckPkt(data []byte, ospfHdrMd *OspfHdrMetadata,
	ipHdrMd *IpHdrMetadata, key IntfConfKey) error {

	link_ack := newospfNeighborLSAACKMsg()
	headers_len := ospfHdrMd.pktlen - OSPF_HEADER_SIZE
	if headers_len >= 20 && headers_len < ospfHdrMd.pktlen {
		fmt.Println("LSAACK: LSA headers length ", headers_len)
		num_headers := int(headers_len / 20)
		server.logger.Info(fmt.Sprintln("LSAACK: Received ", num_headers, " LSA headers."))
		header_byte := make([]byte, num_headers*OSPF_LSA_HEADER_SIZE)
		var start_index uint8
		var lsa_header ospfLSAHeader
		for i := 0; i < num_headers; i++ {
			start_index = uint8(i * OSPF_LSA_HEADER_SIZE)
			copy(header_byte, data[start_index:start_index+20])
			lsa_header = decodeLSAHeader(header_byte)
			server.logger.Info(fmt.Sprintln("LSAACK: Header decoded ",
				"ls_age:options:ls_type:link_state_id:adv_rtr:ls_seq:ls_checksum ",
				lsa_header.ls_age, lsa_header.ls_type, lsa_header.link_state_id,
				lsa_header.adv_router_id, lsa_header.ls_sequence_num,
				lsa_header.ls_checksum))
			link_ack.lsa_headers = append(link_ack.lsa_headers, lsa_header)
		}
	}
	link_ack.nbrId = binary.BigEndian.Uint32(ospfHdrMd.routerId)
	server.neighborLSAACKEventCh <- *link_ack
	return nil
}

func (server *OSPFServer) ProcessLSAAckEvent(msg ospfNeighborLSAACKMsg) {
	server.logger.Info(fmt.Sprintln("LSAACK: Received LSA ACK pkt ", msg))
	nbr, exists := server.NeighborConfigMap[msg.nbrId]
	if !exists {
		server.logger.Info(fmt.Sprintln("LSAACK: Nbr doesnt exist", msg.nbrId))
		return
	}
	discard := server.lsaAckPacketDiscardCheck(nbr)
	if discard {
		return
	}
	/* process each LSA and update request list */
	for index := range msg.lsa_headers {
		/* TODO
		   optimize search technique using sort method */
		req_list := ospfNeighborRequest_list[msg.nbrId]
		reTx_list := ospfNeighborRetx_list[msg.nbrId]
		for in := range req_list {
			if req_list[in].lsa_headers.link_state_id == msg.lsa_headers[index].link_state_id {
				/* invalidate from request list */
				req := newospfNeighborReq()
				req.lsa_headers = msg.lsa_headers[index]

				nbr.req_list_mutex.Lock()
				req_list[in].valid = false
				nbr.req_list_mutex.Unlock()
			}
			/* update the reTxList */
			for in = range reTx_list {
				if reTx_list[in].lsa_headers.link_state_id == msg.lsa_headers[index].link_state_id {
					nbr.retx_list_mutex.Lock()
					reTx_list[in].valid = false
					nbr.retx_list_mutex.Unlock()
				}
			}

		}
	}
}

/*
Link state request packet
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Version #   |       3       |         Packet length         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Router ID                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Area ID                             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Checksum            |             AuType            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Authentication                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Authentication                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          LS type                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Link State ID                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     Advertising Router                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                              ...                              |
*/

func (server *OSPFServer) ProcessLSAReqPkt(data []byte, ospfHdrMd *OspfHdrMetadata, ipHdrMd *IpHdrMetadata, key IntfConfKey) error {
	lsa_req := decodeLSAReqPkt(data, ospfHdrMd.pktlen)
	routerId := convertIPv4ToUint32(ospfHdrMd.routerId)

	lsa_req_msg := ospfNeighborLSAreqMsg{
		nbrKey:    routerId,
		lsa_slice: lsa_req,
	}
	// send the req list to Nbr
	server.logger.Info(fmt.Sprintln("LSAREQ: Decoded LSA packet - ", lsa_req_msg))
	server.neighborLSAReqEventCh <- lsa_req_msg
	return nil
}

/*@fn processLSAReqEvent
  Check LSA req contents and update LSDB appropriately.
*/

func (server *OSPFServer) processLSAReqEvent(msg ospfNeighborLSAreqMsg) {
	server.logger.Info(fmt.Sprintln("LSAREQ: Receieved lsa_req packet for nbr ", msg.nbrKey, " data ", msg.lsa_slice))
	nbrConf, exists := server.NeighborConfigMap[msg.nbrKey]
	if exists {
		for index := range msg.lsa_slice {
			isDiscard := server.lsaReqPacketDiscardCheck(nbrConf, msg.lsa_slice[index])
			if !isDiscard {
				/* TODO
				Flood LSA . */
				server.logger.Info(fmt.Sprintf("LSAREQ: Flood . LSA ", msg.lsa_slice[index]))
			}
		} // enf of for slice
	} // end of exists
}

func (server *OSPFServer) lsaReqPacketDiscardCheck(nbrConf OspfNeighborEntry, req ospfLSAReq) bool {
	if nbrConf.OspfNbrState < config.NbrExchange {
		server.logger.Info(fmt.Sprintln("LSAREQ: Discard .. Nbrstate (expected less than exchange)", nbrConf.OspfNbrState))
		return true
	}
	/* TODO
	check the router DB if packet needs to be updated.
	if not found in LSDB generate LSAReqEvent */

	return false
}

func (server *OSPFServer) lsaAckPacketDiscardCheck(nbrConf OspfNeighborEntry) bool {
	if nbrConf.OspfNbrState < config.NbrExchange {
		server.logger.Info(fmt.Sprintln("LSAACK: Discard .. Nbrstate (expected less than exchange)", nbrConf.OspfNbrState))
		return true
	}
	/* TODO
	check the router DB if packet needs to be updated.
	if not found in LSDB generate LSAReqEvent */

	return false
}

func (server *OSPFServer) lsaUpdDiscardCheck(nbrConf OspfNeighborEntry) bool {
	if nbrConf.OspfNbrState < config.NbrExchange {
		server.logger.Info(fmt.Sprintln("LSAUPD: Discard .. Nbrstate (expected less than exchange)", nbrConf.OspfNbrState))
		return true
	}
	/* TODO
	check the router DB if packet needs to be updated.
	if not found in LSDB generate LSAReqEvent */

	return false
}

func (server *OSPFServer) lsaAddCheck(lsaheader ospfLSAHeader) (result bool) {
	/*
		TODO check if the entry exist in LSDB.
	*/
	return true
}

func (server *OSPFServer) lsaReTxTimerCheck(nbrKey uint32) {
	var lsa_re_tx_check_func func()
	lsa_re_tx_check_func = func() {
		server.logger.Info(fmt.Sprintln("LSARETIMER: Check for rx. Nbr ", nbrKey))
		// check for retx list
		re_list := ospfNeighborRetx_list[nbrKey]
		if len(re_list) > 0 {
			// retransmit packet
			server.logger.Info(fmt.Sprintln("LSATIMER: Send the retx packets. "))
		}
	}
	_, exists := server.NeighborConfigMap[nbrKey]
	if exists {
		nbrConf := server.NeighborConfigMap[nbrKey]
		nbrConf.ospfNeighborLsaRxTimer = time.AfterFunc(RxDBDInterval, lsa_re_tx_check_func)
		//op := NBRUPD
		//server.sendNeighborConf(nbrKey, nbrConf, NbrMsgType(op))
	}
}
