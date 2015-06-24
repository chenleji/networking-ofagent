# Copyright (C) 2015 Hermes Systems
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from ryu.app.ofctl import api as ryu_api
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet import vlan
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp

from neutron.i18n import _LI

import networking_ofagent.plugins.ofagent.agent.metadata as meta


LOG = logging.getLogger(__name__)

class DhcpLib(object):
    _DHCP_CLIENT_PORT = 68
    _DHCP_SERVER_PORT = 67
    _MSG_TYPE_BOOT_REPLY = 2
    _MSG_TYPE_BOOT_REQ = 1

    def __init__(self, ryuapp):
        """Constructor.
        Define the internal table mapped an ip and a mac in a network.
        self._ip_pool_tbl:
            {network1: {mac: {ip_addr:ip_addr, snet_mask:snet_mask, gateway:gateway, dns:dns, static_route:static_route}, ...},
             network2: {mac: {ip_addr:ip_addr, snet_mask:snet_mask, gateway:gateway, dns:dns, static_route:static_route}, ...},
             ...,
            }

        :param ryuapp: object of the ryu app.
        """
        self.ryuapp = ryuapp
        self._ip_pool_tbl = {}
        self.br = None

    def set_bridge(self, br):
        self.br = br

    @log_helpers.log_method_call
    def _send_dhcp_reply(self, datapath, port, pkt):
        ofp = datapath.ofproto
        ofpp = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [ofpp.OFPActionOutput(port=port)]
        out = ofpp.OFPPacketOut(datapath=datapath,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=ofp.OFPP_CONTROLLER,
                                actions=actions,
                                data=data)
        ryu_api.send_msg(self.ryuapp, out)

    @log_helpers.log_method_call
    def add_ip_pool_table_entry(self, network, mac, ip_addr, snet_mask, gateway, dns, dhcp_server):
        entry = {'ip_addr': ip_addr,
                 'snet_mask': snet_mask,
                 'gateway': gateway,
                 'dns': dns,
                 'dhcp_server': dhcp_server
                 }
        if network in self._ip_pool_tbl:
            self._ip_pool_tbl[network][mac] = entry
        else:
            self._ip_pool_tbl[network] = {mac: entry}

    @log_helpers.log_method_call
    def del_ip_pool_table_entry(self, network, mac):
        if network not in self._ip_pool_tbl:
            LOG.debug("removal of unknown network %s", network)
            return
        if self._ip_pool_tbl[network].pop(mac, None) is None:
            LOG.debug("removal of unknown mac %s", mac)
            return
        if not self._ip_pool_tbl[network]:
            del self._ip_pool_tbl[network]

    def packet_in_handler(self, ev):
        """Check a packet-in message.

           Build and output an dhcp reply if a packet-in message is
           an dhcp packet.
        """
        msg = ev.msg
        LOG.debug("packet-in msg %s", msg)
        datapath = msg.datapath
        if self.br is None:
            LOG.info(_LI("No bridge is set"))
            return
        if self.br.datapath.id != datapath.id:
            LOG.info(_LI("Unknown bridge %(dpid)s ours %(ours)s"),
                     {"dpid": datapath.id, "ours": self.br.datapath.id})
            return
        ofp = datapath.ofproto
        port = msg.match['in_port']
        metadata = msg.match.get('metadata')
        # NOTE(yamamoto): Ryu packet library can raise various exceptions
        # on a corrupted packet.
        try:
            pkt = packet.Packet(msg.data)
        except Exception as e:
            LOG.debug("Unparsable packet: got exception %s", e)
            return
        LOG.debug("packet-in dpid %(dpid)s in_port %(port)s pkt %(pkt)s",
                  {'dpid': dpid_lib.dpid_to_str(datapath.id),
                  'port': port, 'pkt': pkt})

        if metadata is None:
            LOG.info(_LI("drop non tenant packet"))
            return
        network = metadata & meta.NETWORK_MASK
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            LOG.debug("drop non-ethernet packet")
            return
        pkt_vlan = pkt.get_protocol(vlan.vlan)
        if pkt_vlan is None:
            return
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip is None:
            return
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_udp is None:
            return
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        if pkt_dhcp is None:
            LOG.debug("drop non-dhcp packet")
            return

        iptbl = self._ip_pool_tbl.get(network)
        if iptbl:
            if self._respond_dhcp(datapath, port, iptbl,
                                 pkt_ethernet, pkt_vlan, pkt_udp, pkt_dhcp):
                return
        else:
            LOG.info(_LI("unknown network %s"), network)

        # send an unknown arp packet to the table.
        self._send_unknown_packet(msg, port, ofp.OFPP_TABLE)

    @log_helpers.log_method_call
    def _send_unknown_packet(self, msg, in_port, out_port):
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofpp = datapath.ofproto_parser
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        actions = [ofpp.OFPActionOutput(port=out_port)]
        out = ofpp.OFPPacketOut(datapath=datapath,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=actions,
                                data=data)
        ryu_api.send_msg(self.ryuapp, out)

    def _respond_dhcp(self, datapath, port, iptbl,
                     pkt_ethernet, pkt_vlan, pkt_udp, pkt_dhcp):
        hw_addr = pkt_dhcp.chaddr
        entry = iptbl.get(hw_addr)
        if entry is None:
            LOG.debug("unknown ip request for mac: %s", hw_addr)
            return False

        ip_addr = entry['ip_addr']
        snet_mask = entry['snet_mask']
        siaddr = entry['gate_way']    # gateway ip addr
        dns = entry['dns']
        dhcp_server = entry['dhcp_server']
        lease_time = 180
        msg_type_opt = dhcp.DHCP_DISCOVER
        msg_type = dhcp.DHCP_ACK
        req_ip_addr = None
        sel_server_id = None

        # DHCP message type code
        for option in entry['options']:
            if option.tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                msg_type_opt = option.value
            if option.tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT:
                req_ip_addr = option.value
            if option.tag == dhcp.DHCP_SERVER_IDENTIFIER_OPT:
                sel_server_id = option.value

        if sel_server_id != dhcp_server:
            LOG.debug("unknown dhcp server (%s) was selected!", sel_server_id)
            return False
        if msg_type_opt == dhcp.DHCP_DISCOVER:
            msg_type = dhcp.DHCP_OFFER
        if msg_type_opt == dhcp.DHCP_REQUEST:
            if req_ip_addr == ip_addr:
                msg_type = dhcp.DHCP_ACK
            else:
                msg_type = dhcp.DHCP_NAK

        # DHCP options tag code
        option_list = list()
        option_list.append(dhcp.option(dhcp.DHCP_MESSAGE_TYPE_OPT, msg_type, length=1))
        if msg_type_opt != dhcp.dhcp.DHCP_NAK:
            option_list.append(dhcp.option(dhcp.DHCP_SUBNET_MASK_OPT, snet_mask, length=4))
            option_list.append(dhcp.option(dhcp.DHCP_GATEWAY_ADDR_OPT, siaddr, length=4))
            option_list.append(dhcp.option(dhcp.DHCP_DNS_SERVER_ADDR_OPT, dns, length=4))
            option_list.append(dhcp.option(dhcp.DHCP_SERVER_IDENTIFIER_OPT, dhcp_server, length=4))
            option_list.append(dhcp.option(dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, lease_time, length=4))
            option_list.append(dhcp.option(dhcp.DHCP_RENEWAL_TIME_OPT, lease_time/2, length=4))
            option_list.append(dhcp.option(dhcp.DHCP_REBINDING_TIME_OPT, lease_time*7/8, length=4))
        options = dhcp.options(option_list=option_list, options_len=len(option_list))

        LOG.debug("responding dhcp request %(hw_addr)s -> %(ip_addr)s",
                  {'hw_addr': hw_addr, 'ip_addr': ip_addr})
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=hw_addr))
        if pkt_vlan:
            pkt.add_protocol(vlan.vlan(cfi=pkt_vlan.cfi,
                                       ethertype=pkt_vlan.ethertype,
                                       pcp=pkt_vlan.pcp,
                                       vid=pkt_vlan.vid))
        pkt.add_protocol(udp.udp(src_port=pkt_udp.dst_port, dst_port=pkt_udp.src_port))
        pkt.add_protocol(dhcp.dhcp(op=self._MSG_TYPE_BOOT_REPLY, chaddr=pkt_dhcp.chaddr, options=options,
                                    ciaddr=pkt_dhcp.ciaddr, yiaddr=ip_addr, siaddr=siaddr,
                                    giaddr='0.0.0.0', sname='', boot_file=''))
        self._send_dhcp_reply(datapath, port, pkt)
        return True