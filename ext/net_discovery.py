"""
Perform a network discovery by flooding messages out of all ports of a switch.
The messages are then analyzed by the central controller to get a global view
of the whole network.

Here we use ICMP echo requests, where the openflow switches will report the
message to the central controller, and the end hosts will issue an ICMP echo
reply and send it back to a switch, then again the message will be passed to
the central controller.

Yujia Li, 12/2012
"""

from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.revent import *
from pox.lib.packet import *
from pox.lib.packet.ipv4 import IP_ANY, IP_BROADCAST
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST
from pox.lib.recoco import Timer

import pox.openflow.libopenflow_01 as of

from netvis import NetVis, NetVisMsg, Switch, Host

import thread

from collections import namedtuple

log = core.getLogger()
netvis = core.netvis

class MyPort (object):
  """
  A port is a network interface for openflow switches, it can connect to hosts
  and other controllers
  """
  def __init__ (self, switch, pid, mac):
    self.switch = switch
    self.pid = pid
    self.mac = mac
    self.neighbor_hosts = set()
    self.neighbor_ports = set()

  def has_link (self, node):
    if isinstance(node, MyHost):
      return (node in self.neighbor_hosts)
    elif isinstance(node, MyPort):
      return (node in self.neighbor_ports)
    else:
      log.warning('Invalid node type in MyPort.has_link')
      return None

  def add_link (self, node):
    """
    Add link and write a message to netvis
    """
    if isinstance(node, MyHost):
      self.neighbor_hosts.add(node)
      # when adding a host, the port should be a flood port as well
      #self.enable_flood()
      desc = "h%d (%s) <--> s%d-port%d" % (node.hid, node.ip, self.switch.dpid,
          self.pid)
      netvis.writeMsg(NetVisMsg(
        NetVisMsg.MSG_TYPE_ADD, NetVisMsg.MSG_OBJ_TYPE_LINK,
        src=self.switch._switch, dst=node._host, desc=desc))
    elif isinstance(node, MyPort):
      self.neighbor_ports.add(node)
      desc = "s%d-port%d <--> s%d-port%d" % (node.switch.dpid, node.pid, 
          self.switch.dpid, self.pid)
      netvis.writeMsg(NetVisMsg(
        NetVisMsg.MSG_TYPE_ADD, NetVisMsg.MSG_OBJ_TYPE_LINK,
        src=self.switch._switch, dst=node.switch._switch, desc=desc))
    else:
      log.warning('Invalid node type in MyPort.add_link')

  def add_link_no_send (self, node):
    """
    Add link but do not write a message to netvis
    """
    if isinstance(node, MyHost):
      self.neighbor_hosts.add(node)
    elif isinstance(node, MyPort):
      self.neighbor_ports.add(node)
    else:
      log.warning('Invalid node type in MyPort.add_link_no_send')

  def __eq__ (self, other):
    if not isinstance(other, MyPort):
      return False
    else:
      return (self.mac is not None) and (self.mac == other.mac)
  
  def __ne__ (self, other):
    return (not self.__eq__(other))

  def __hash__ (self):
    return self.mac.__hash__()

  def enable_flood (self):
    self.switch._add_flood_port(self.pid)

  def disable_flood (self):
    self.switch._remove_flood_port(self.pid)

  def update_flood_ports (self, minid):
    self.switch._update_flood_ports(minid, self.pid)

  def get_flood_minid (self):
    return self.switch._get_flood_minid()

class MySwitch (object):
  """
  Representation for a switch in the network, it contains a connection to the
  switch so it can be used to send messages to the switch
  """
  def __init__ (self, dpid, connection, ports=None):
    self.dpid = dpid
    self.connection = connection
    self.ports = {}   # map from port number to MyPort class
    self.mac_to_port = {} # map from mac address to MyPort class

    # Used for flooding messages - spanning tree algorithm will use them
    # XXX: Note the spanning tree algorithm only works for point-to-point
    # links, which is the case for Mininet.
    self.flood_ports = set()  # a set of port numbers
    self.minid = dpid

    # ports should be a iterable collection of ofp_phy_port
    if ports is not None:
      for port in ports:
        # don't add virtual ports
        if port.port_no < of.ofp_port_rev_map['OFPP_MAX']:
          self.add_port(port.port_no, port.hw_addr)
          # By default, all ports are 'floodable'
          self.flood_ports.add(port.port_no)

    # Switch object used in netvis
    self._switch = Switch('s' + str(dpid), self.get_desc()) 

  def _update_flood_ports (self, new_minid, from_pid):
    self.minid = new_minid
    for pid in self.flood_ports:
      if pid == from_pid:
        continue
      port = self.ports[pid]
      for dst_port in port.neighbor_ports:
        dst_port.update_flood_ports(new_minid)

  def _add_flood_port (self, pid):
    self.flood_ports.add(pid)

  def _remove_flood_port (self, pid):
    if pid in self.flood_ports:
      self.flood_ports.remove(pid)

  def _get_flood_minid (self):
    return self.minid

  def get_desc (self):
    desc = 'Switch %s' % ('s' + str(self.dpid))
    for pid, port in self.ports.iteritems():
      desc += '\nport%d: %s' % (pid, port.mac)
    return desc

  def has_port (self, pid):
    return (pid in self.ports)

  def add_port (self, pid, mac):
    port = MyPort(self, pid, mac)
    self.ports[pid] = port
    if mac is not None:
      self.mac_to_port[mac] = port
    return port

  def get_port_by_mac (self, mac):
    if mac in self.mac_to_port:
      return self.mac_to_port[mac]
    else:
      return None

  def get_port_by_id (self, pid):
    if (pid in self.ports):
      return self.ports[pid]
    else:
      return None

  def send_arp_probe (self):
    """
    Send ARP probe packets out of all ports on this switch, the ARP probe
    messages will have all zero IP address for both source and destination.
    Normal hosts should ignore these ARP messages, but we can ask the switches
    to handle such messages correctly.
    """
    for pid, port in self.ports.iteritems():
      packet_out = self.create_arp_probe_packet(port)
      log.debug('Sending ARP probe messages out of s%d-port%d', self.dpid, pid)
      self.connection.send(packet_out)

  def create_arp_probe_packet (self, port):
    "Create ARP probe packet to be sent out a given port"
    arp_packet = arp()
    arp_packet.hwsrc = port.mac
    arp_packet.hwdst = ETHER_ANY
    arp_packet.protosrc = IP_ANY
    arp_packet.protodst = IP_ANY
    arp_packet.opcode = arp.REQUEST

    eth_packet = ethernet()
    eth_packet.src = port.mac
    eth_packet.dst = ETHER_BROADCAST
    eth_packet.set_payload(arp_packet)
    eth_packet.type = ethernet.ARP_TYPE

    po = of.ofp_packet_out(action = of.ofp_action_output(port=port.pid),
                           data = eth_packet.pack())
    return po 


class MyHost (object):
  """
  Two hosts are considered to be the same if they have the same IP address.
  Hosts only have one network interface, otherwise it is impossible to
  distinguish one host with mutiple interfaces and multiple hosts.
  """

  DESC_TEMPLATE = 'Host %s\nIP: %s\nMAC: %s'

  def __init__ (self, hid, ip=None, mac=None):
    self.ip = ip
    self.mac = mac
    # self.hid = hid
    self.hid = ip.toUnsigned() & 0x00ffffff # remove the first byte
    # Host object used in netvis
    self._host = Host('h' + str(self.hid), self.get_desc())

  def get_desc (self):
    return MyHost.DESC_TEMPLATE % ('h'+str(self.hid), self.ip, self.mac)

  def __eq__ (self, other):
    if not isinstance(other, MyHost):
      return False
    else:
      return self.ip == other.ip and self.mac == other.mac
  
  def __ne__ (self, other):
    return (not self.__eq__(other))

  def __hash__ (self):
    return self.ip.toUnsigned()


class MyNetwork (object):
  """
  class for the detected network.
  """
  def __init__ (self):
    self.switches = {}  # indexed by dpid
    self.hosts = {}     # indexed by IP
    self.links = {}
    self.next_hostid = 1

  def get_switch (self, sid):
    if sid in self.switches:
      return self.switches[sid]
    else:
      return None

  def get_host (self, ip, mac=None):
    if ip in self.hosts:
      host = self.hosts[ip]
      if (mac is not None) and (not host.mac == mac):
        log.warning('IP and MAC mismatch for h%d', host.hid)
        return None
      else:
        return host
    else:
      return None

  def get_port_by_mac (self, mac):
    # Search through all switches in the network.
    # This is not very efficient but can be improved.
    for sid, switch  in self.switches.iteritems():
      port = switch.get_port_by_mac(mac)
      if port is not None:
        return port
    return None

  def add_switch (self, dpid, conn, ports):
    """
    Create and then add a switch to the network, and write a message to netvis
    """
    switch = MySwitch(dpid, conn, ports)
    self.switches[dpid] = switch

    netvis.writeMsg(NetVisMsg(
      NetVisMsg.MSG_TYPE_ADD, NetVisMsg.MSG_OBJ_TYPE_SWITCH, 
      switch=switch._switch))

    return switch

  def add_host (self, ip, mac=None):
    """
    Create and then add a host to the network, and write a message to netvis
    """
    host = MyHost(self.next_hostid, ip, mac)
    self.hosts[host.ip] = host

    netvis.writeMsg(NetVisMsg(
      NetVisMsg.MSG_TYPE_ADD, NetVisMsg.MSG_OBJ_TYPE_HOST, host=host._host))

    self.next_hostid += 1
    return host

  def print_network (self):
    for sid, switch in self.switches.iteritems():
      for pid, port in switch.ports.iteritems():
        for host in port.neighbor_hosts:
          log.debug("s%d-port%d --> h%d, ip:%s, mac:%s", sid, pid, 
              host.hid, str(host.ip), str(host.mac))
        for nport in port.neighbor_ports:
          log.debug("s%d-port%d --> s%d-port%d", sid, pid, 
              nport.switch.dpid, nport.pid)

class ArpReq (object):
  def __init__ (self, ip_dst, ip_src, in_port):
    self.ip_dst = ip_dst
    self.ip_src = ip_src
    self.in_port = in_port

PendingIpPacket = namedtuple('PendingIpPacket', ['packet', 'in_port'])

class SwitchController (EventMixin):
  """
  This controller is used for each switch, used to forward ethernet packets
  """
  def __init__ (self, switch):
    self.switch = switch
    self.connection = switch.connection
    self.listenTo(self.connection)
    self.mac_to_port = {}   # map MAC addresses to port
    self.ip_to_port = {}    # map IP addresses to port 
    self.ip_to_mac = {}     # map IP to next hop mac
    self.pending_arp_reqs = []  # set of pending ARP requests to be replied
    self.pending_ip_packet = [] # set of pending IP packets waiting for ARP

  def _handle_PacketIn (self, event):
    log.debug('In SwitchController._handle_PacketIn for s%d', self.switch.dpid)
    ofp = event.ofp
    in_port = event.port
    eth_packet = event.parsed

    if not eth_packet.parsed:
      # ignore incomplate packets
      log.debug('Packet not parsed @ s%d', self.switch.dpid)
      return

    eth_dst = eth_packet.dst
    eth_src = eth_packet.src

    self.mac_to_port[eth_src] = self.switch.get_port_by_id(in_port)

    if eth_dst == ETHER_BROADCAST:
      # broadcast message, only handle ARP
      if eth_packet.type == ethernet.ARP_TYPE:
        self.handle_arp(eth_packet, event)
      # drop all other broadcast messages
      return

    if eth_dst == self.switch.get_port_by_id(in_port).mac:
      # this packet is directed to us! only handle ARP and IP
      if eth_packet.type == ethernet.ARP_TYPE:
        self.handle_arp(eth_packet, event)
      if eth_packet.type == ethernet.IP_TYPE:
        self.handle_ip(eth_packet, event)
      # for all other types, drop the packet
      return

  def handle_arp (self, eth_packet, event):
    log.debug('In SwitchController.handle_arp! for s%d', self.switch.dpid)

    arp_packet = eth_packet.payload
    in_port = self.switch.get_port_by_id(event.port)
    ip_dst = arp_packet.protodst
    ip_src = arp_packet.protosrc

    # ignore ARP probing messages
    if ip_src == IP_ANY:
      log.debug('ARP probing message received...')
      return

    # update ip to port and next hop mac mapping
    log.debug('Updating ip->port & ip->mac mapping.')
    self.ip_to_port[ip_src] = in_port
    self.ip_to_mac[ip_src] = arp_packet.hwsrc

    # Notify ARP request queue about the new IP
    self.remove_pending_arp_req(ip_src, in_port)
    self.notify_pending_arp_req(ip_src)
    self.notify_pending_ip_packet(ip_src)

    if arp_packet.opcode == arp.REQUEST:
      log.debug('Handle arp request')
      # check if we have the dst ip
      if ip_dst in self.ip_to_port:
        # generate ARP reply
        arp_packet.protodst = ip_src 
        arp_packet.hwdst = arp_packet.hwsrc
        arp_packet.protosrc = ip_dst
        arp_packet.hwsrc = in_port.mac
        arp_packet.opcode = arp.REPLY

        eth_packet.dst = eth_packet.src
        eth_packet.src = in_port.mac

        log.debug('Sending ARP reply out of s%d-port%d', self.switch.dpid,
            in_port.pid)
        self.send_packet(-1, eth_packet.pack(), 
            of.ofp_port_rev_map['OFPP_IN_PORT'], event.port)
      else:
        log.debug('Unknown IP in ARP request: %s', ip_dst)
        # flood ARP requet, but change hwsrc
        self.flood_arp_request(ip_dst, ip_src, event.port)
        # start a timer so that we can send back replies once we hear back
        # from the ARP flood
        # Timer(0.3, self.reply_arp, args=[ip_dst, ip_src, in_port])
        self.try_add_pending_arp_req(ip_dst, ip_src, in_port)

  def remove_pending_arp_req (self, ip_dst, in_port):
    toremove = []
    for arpreq in self.pending_arp_reqs:
      if arpreq.ip_dst == ip_dst and arpreq.in_port == in_port:
        toremove.append(arpreq)
    for arpreq in toremove:
      self.pending_arp_reqs.remove(arpreq)

  def try_add_pending_arp_req (self, ip_dst, ip_src, in_port):
    for arpreq in self.pending_arp_reqs:
      if arpreq.ip_dst == ip_dst and arpreq.ip_src == ip_src:
        return
    log.debug('Adding pending ARP request for %s', ip_dst)
    self.pending_arp_reqs.append(ArpReq(ip_dst, ip_src, in_port))

  def notify_pending_arp_req (self, ip_dst):
    log.debug('Notifying pending ARP queue for %s', ip_dst)
    toremove = []
    for arpreq in self.pending_arp_reqs:
      if arpreq.ip_dst == ip_dst:
        self.reply_arp(ip_dst, arpreq.ip_src, arpreq.in_port)
        toremove.append(arpreq)
    for arpreq in toremove:
      self.pending_arp_reqs.remove(arpreq)

  def reply_arp (self, ip_dst, ip_src, in_port):
    log.debug('Try to reply ARP request -- s%d', self.switch.dpid)
    if ip_dst not in self.ip_to_port:
      # if the destination IP is still not in our table, simply drop the
      # packet
      log.debug("Still don't know about the requested ARP -- s%d",
          self.switch.dpid)
      return

    # if we now have the destination IP, send a reply back
    eth_packet = ethernet()
    eth_packet.src = in_port.mac
    eth_packet.dst = self.ip_to_mac[ip_src]
    eth_packet.type = ethernet.ARP_TYPE

    arp_packet = arp()
    arp_packet.hwsrc = in_port.mac
    arp_packet.protosrc = ip_dst
    arp_packet.hwdst = self.ip_to_mac[ip_src]
    arp_packet.protodst = ip_src
    arp_packet.opcode = arp.REPLY

    eth_packet.set_payload(arp_packet)

    log.debug('Sending ARP reply out of s%d-port%d', self.switch.dpid,
        in_port.pid)
    self.send_packet(-1, eth_packet.pack(),
        of.ofp_port_rev_map['OFPP_IN_PORT'], in_port.pid)

  def handle_ip (self, eth_packet, event):
    log.debug('In SwitchController.handle_ip!')

    ip_packet = eth_packet.payload
    in_port = self.switch.get_port_by_id(event.port)
    eth_src = eth_packet.src
    ip_dst = ip_packet.dstip
    ip_src = ip_packet.srcip

    self.ip_to_port[ip_src] = in_port
    self.ip_to_mac[ip_src] = eth_src

    if ip_dst in self.ip_to_port:
      # we have the destination IP address, forward it
      port = self.ip_to_port[ip_dst]

      eth_packet.src = port.mac
      eth_packet.dst = self.ip_to_mac[ip_dst]

      log.debug('Forwarding IP packets out of s%d-port%d, dst %s', 
          self.switch.dpid, port.pid, ip_dst)
      self.send_packet(-1, eth_packet.pack(), port.pid, event.port)

      # install a rule for forwarding IP packets to the destination, since it
      # is already in the forwarding table, it would not affect other parts of
      # the program to function correctly
      #msg = of.ofp_flow_mod()
      #match = of.ofp_match()
      #match.set_nw_dst(ip_dst)
      #match.nw_dst = ip_dst
      #msg.match = match
      #msg.match = of.ofp_match.from_packet(eth_packet)
      #log.debug(msg.match.show())
      #msg.actions.append(of.ofp_action_output(port = port.pid))
      #msg.actions.append(of.ofp_action_dl_addr.set_src(port.mac))

      #self.connection.send(msg)
      #log.debug('Installing rule %s -> s%d-port%d', ip_dst, self.switch.dpid,
      #    port.pid)
    else:
      # we don't have the destination IP address, drop it and send ARP
      # requests
      log.debug('Unknown IP in IP packet: %s', ip_dst)
      self.flood_arp_request(ip_dst, ip_src, event.port)
      self.try_add_pending_arp_req(ip_dst, ip_src, in_port)
      self.add_pending_ip_packet(ip_packet, in_port)

  def add_pending_ip_packet (self, ip_packet, in_port):
    self.pending_ip_packet.append(PendingIpPacket(ip_packet, in_port))

  def notify_pending_ip_packet (self, ip_dst):
    # send all IP packets waiting for MAC address of a given destination IP
    port = self.ip_to_port[ip_dst]

    eth_packet = ethernet()
    eth_packet.src = port.mac
    eth_packet.dst = self.ip_to_mac[ip_dst]
    eth_packet.type = ethernet.IP_TYPE

    toremove = []

    for ip_packet in self.pending_ip_packet:
      if ip_packet.packet.dstip == ip_dst:
        eth_packet.set_payload(ip_packet.packet)
        log.debug('Send delayed IP packet out of s%d-port%d, dst %s',
            self.switch.dpid, port.pid, ip_dst)
        self.send_packet(-1, eth_packet.pack(), port.pid,
            ip_packet.in_port.pid)
        toremove.append(ip_packet)
    for ip_packet in toremove:
      self.pending_ip_packet.remove(ip_packet)

  def flood_arp_request (self, ip_dst, ip_src, in_portid):
    eth_packet = ethernet()
    arp_packet = arp()

    eth_packet.set_payload(arp_packet)
    eth_packet.dst = ETHER_BROADCAST
    eth_packet.type = ethernet.ARP_TYPE

    arp_packet.hwdst = ETHER_BROADCAST
    arp_packet.protodst = ip_dst
    arp_packet.protosrc = ip_src
    arp_packet.opcode = arp.REQUEST

    for pid in self.switch.flood_ports:
      if not pid == in_portid:
        port = self.switch.get_port_by_id(pid)

        eth_packet.src = port.mac
        arp_packet.hwsrc = port.mac

        log.debug('Flooding ARP request out of s%d-port%d', self.switch.dpid,
            port.pid)
        self.send_packet(-1, eth_packet.pack(), port.pid, in_portid)

  def send_packet (self, buffer_id, raw_data, out_port, in_port):
    msg = of.ofp_packet_out()
    msg.in_port = in_port

    if buffer_id != -1 and buffer_id is not None:
      # We got a buffer ID from the switch; use that
      msg.buffer_id = buffer_id
    else:
      # No buffer ID from switch -- we got the raw data
      if raw_data is None:
        # No raw_data specified -- nothing to send!
        return
      msg.data = raw_data

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


class Controller (EventMixin):
  """
  The controller that implements network discovery by sending out ICMP
  packets. This only applies for a single switch.
  """
  def __init__ (self):
    self.listenTo(core.openflow)
    self.net = MyNetwork()
    self.mactoport= {}
    self.timer = Timer(3, self.visualization_handler, recurring=True)
  
  def _handle_PacketIn (self, event):
    conn = event.connection
    dpid = event.dpid
    ofp = event.ofp
    portid = event.port
    eth_packet = event.parsed

    if not eth_packet.parsed:
      # ignore incomplete packets
      return

    log.debug("---> Packet received from s%s, port %d", dpid, portid)

    # handle the port
    switch = self.net.get_switch(dpid)
    if switch is None:
      #switch = self.net.add_switch(dpid, conn)
      log.warning("Unregistered switch! in _handle_PacketIn")
      return

    port = switch.get_port_by_id(portid)
    if port is None:
      #port = switch.add_port(portid)
      log.warning("Unregistered port! in _handle_PacketIn")
      return

    # learn IP & MAC of the source using Ethernet/ARP messages
    src_mac = eth_packet.src

    # check if the source is a switch port
    src_port = self.net.get_port_by_mac(src_mac)
    if src_port is not None:
      port_has_link = port.has_link(src_port)
      srcport_has_link = src_port.has_link(port)
      if not port_has_link == srcport_has_link:
        log.warning("port and srcport disagree on a link! in _handle_PacketIn")
      else:
        if not port_has_link:
          # send only one message to netvis
          port.add_link(src_port)
          src_port.add_link_no_send(port)

          # handle spanning tree algorithm
          minid = port.get_flood_minid()
          src_minid = src_port.get_flood_minid()

          if minid == src_minid:
            # The two ports are already connected in the flooding tree
            port.disable_flood()
            src_port.disable_flood()
          else:
            # The two ports are not connected, then add the connection
            #port.enable_flood()
            #src_port.enable_flood()

            if minid > src_minid:
              port.update_flood_ports(src_minid)
            else:
              src_port.update_flood_ports(minid)

      # port-port connection established
      return

    # source is not a swithc port, then it should be a host, handle ARP and IP
    # packets
    if eth_packet.type == ethernet.ARP_TYPE:
      arp_packet = eth_packet.payload

      if not arp_packet.hwsrc == src_mac:
        # make sure this is a packet from host
        log.warning('ARP eth_src != ETH src for packet from host!')
        return

      src_ip = arp_packet.protosrc

      if src_ip == IP_ANY:  # drop invalid IP addresses
        return
    elif eth_packet.type == ethernet.IP_TYPE:
      ip_packet = eth_packet.payload
      src_ip = ip_packet.srcip
      if src_ip == IP_ANY: # drop invalid IP addresses
        return
    else: # drop non-ARP messages
      return
    
    host = self.net.get_host(src_ip, src_mac)
    if host is None:
      host = self.net.add_host(src_ip, src_mac)
      port.add_link(host)
    else:
      if not port.has_link(host):
        port.add_link(host)

  def _handle_ConnectionUp (self, event):
    log.debug("---> Connection set up with %d", event.dpid)
    switch = self.net.add_switch(event.dpid, event.connection, event.ofp.ports)
    switch.send_arp_probe()   # send ARP probe messages out of all ports
    SwitchController(switch)

  def analyze_packet(self, pkt):
    pass

  def visualization_handler (self):
    log.debug("**********************")
    self.net.print_network()
    

def launch ():
  log.debug("---> Controller launched!")
  Controller()

