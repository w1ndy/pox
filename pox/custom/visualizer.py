from pox.core import core
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventHalt
from pox.lib.revent.revent import *
from pox.lib.packet import ethernet, arp, icmp, echo, ipv4, TYPE_ECHO_REQUEST
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

from random import randrange
from time import time

import pox.openflow.libopenflow_01 as of

SAMPLE_RATE 	= 1.0
PROBE_FREQUENCY = 1.0
LOG_FREQUENCY	= 5.0

SPEED_UNIT = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s']
FAKE_ETHADDR = EthAddr('01:23:45:67:89:ab')
FAKE_IPADDR = IPAddr('254.254.254.254')

def generate_random_mac():
	#return '%02x:%02x:%02x:%02x:%02x:%02x' % (randrange(255), randrange(255), randrange(255), randrange(255), randrange(255), randrange(255))
	return '6c:3b:e5:84:%02x:%02x' % (randrange(255), randrange(255))

def generate_random_ip():
	return '10.0.%d.%d' % (randrange(254), randrange(254))

class QualityProber(object):
	def __init__(self, switch1, port1, switch2, port2, s_to_h = False):
		self.switch1 = switch1
		self.port1 = port1
		self.switch2 = switch2
		self.port2 = port2
		self.s_to_h = s_to_h
		self.fake_hwaddr = generate_random_mac()
		self.fake_hwaddr2 = generate_random_mac()
		while self.fake_hwaddr2 == self.fake_hwaddr:
			self.fake_hwaddr2 = generate_random_mac()
		self.fake_ipaddr = generate_random_ip()
		self.installed = False

		self.total_ping = 0
		self.effective_ping = 0
		self.ping_lost = 0
		self.total_rtt = 0.0
		self.last_detect_time = 0.0
		self.timer = None

	def get_source(self):
		return self.switch1

	def get_destination(self):
		return self.switch2

	def get_hwaddr(self):
		return self.fake_hwaddr

	def reset(self):
		if self.timer:
			self.timer.cancel()
			self.timer = None

	def is_detecting(self):
		return self.timer != None

	def detect(self):
		arp_req = arp()
		arp_req.opcode = arp.REQUEST
		arp_req.hwsrc = EthAddr(self.fake_hwaddr)
		arp_req.hwdst = EthAddr('00:00:00:00:00:00')
		arp_req.protosrc = IPAddr(self.fake_ipaddr)

		ether = ethernet()
		ether.type = ethernet.ARP_TYPE
		ether.src = EthAddr(self.fake_hwaddr)

		if not self.s_to_h:
			# print ' # Detecting a switch-to-switch link...'
			arp_req.hwdst = EthAddr(self.fake_hwaddr)
			ether.src = EthAddr(self.fake_hwaddr2)
			ether.dst = EthAddr(self.fake_hwaddr)
		else:
			# print ' # Detecting a switch-to-host link...'
			macEntry = core.host_tracker.getMacEntry(EthAddr(self.switch2))
			if macEntry and len(macEntry.ipAddrs) > 0:
				arp_req.protodst = macEntry.ipAddrs.keys()[0]
			else:
				#print '   ! WARNING: Layer 3 address not found.'
				return
			ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')

		if not self.installed:
			if not self.s_to_h:
				# msg = of.ofp_flow_mod()
				# msg.priority = 65530
				# msg.match.dl_dst = EthAddr(self.fake_hwaddr)
				# msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
				# core.openflow.sendToDPID(str_to_dpid(self.switch1), msg)

				msg = of.ofp_flow_mod()
				msg.priority = 65529
				msg.match.dl_dst = EthAddr(self.fake_hwaddr)
				msg.actions.append(of.ofp_action_output(port = self.port1))
				core.openflow.sendToDPID(str_to_dpid(self.switch1), msg)

				msg = of.ofp_flow_mod()
				msg.priority = 65529
				msg.match.dl_dst = EthAddr(self.fake_hwaddr)
				msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
				core.openflow.sendToDPID(str_to_dpid(self.switch2), msg)

				# msg = of.ofp_flow_mod()
				# msg.priority = 65530
				# msg.match.dl_dst = EthAddr(self.fake_hwaddr2)
				# msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.fake_hwaddr)))
				# msg.actions.append(of.ofp_action_output(port = self.port2))
				# core.openflow.sendToDPID(str_to_dpid(self.switch2), msg)
			else:
				msg = of.ofp_flow_mod()
				msg.priority = 65530
				msg.match.dl_dst = EthAddr(self.fake_hwaddr)
				msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
				core.openflow.sendToDPID(str_to_dpid(self.switch1), msg)
			self.installed = True

		ether.payload = arp_req
		# print '   * Sending ARP:', str(arp_req)

		msg = of.ofp_packet_out()
		msg.data = ether
		msg.actions.append(of.ofp_action_output(port = self.port1))
		core.openflow.sendToDPID(str_to_dpid(self.switch1), msg)

		self.last_detect_time = time()
		self.total_ping += 1
		self.timer = Timer(1, self._time_out, recurring = False)

	def _packet_in(self):
		if self.timer:
			self.timer.cancel()
			self.timer = None

		timed = time() - self.last_detect_time
		if self.s_to_h:
			timed /= 2.0
		self.total_rtt += timed
		self.effective_ping += 1
		#print ' # Link between %s and %s latency %.3f, avg %.3f, loss %.1f%%' % (self.switch1, self.switch2, timed, self.total_rtt / self.effective_ping, float(self.ping_lost) / float(self.total_ping) * 100.0)

	def _time_out(self):
		self.ping_lost += 1
		self.timer = None
		#print ' # Link between %s and %s timed out, avg %.3f, loss %.1f%%' % (self.switch1, self.switch2, self.total_rtt / (1 if self.effective_ping == 0 else self.effective_ping), float(self.ping_lost) / float(self.total_ping) * 100.0)

class QualityProbeManager (object):
	def __init__(self):
		self.hosts = None
		self.switches = None
		self.prober_by_hwaddr = {}
		self.prober_by_id = {}
		self._t = Timer(PROBE_FREQUENCY, self.kick_once, recurring = True)

	def update_table(self, hosts, switches):
		self.hosts = hosts
		self.switches = switches

	def install(self, hwaddr_a, port_a, hwaddr_b, port_b, link_id):
		print ' # installing new prober...'
		new_prober = None
		if hwaddr_a in self.hosts:
			new_prober = QualityProber(hwaddr_b, port_b, hwaddr_a, port_a, True)
		elif hwaddr_b in self.hosts:
			new_prober = QualityProber(hwaddr_a, port_a, hwaddr_b, port_b, True)
		else:
			new_prober = QualityProber(hwaddr_a, port_a, hwaddr_b, port_b)
		self.prober_by_hwaddr[new_prober.get_hwaddr()] = new_prober
		if hwaddr_a > hwaddr_b:
			hwaddr_a, hwaddr_b = hwaddr_b, hwaddr_a

		if not link_id in self.prober_by_id:
			self.prober_by_id[link_id] = new_prober
		else:
			print ' ! WARNING: probe already exists.'

	def uninstall(self, link_id):
		if link_id in self.prober_by_id:
			self.prober_by_id[link_id].reset()
			del self.prober_by_hwaddr[self.prober_by_id[link_id].get_hwaddr()]
			del self.prober_by_id[link_id]

	def get_prober(self, link_id):
		if link_id in self.prober_by_id:
			return self.prober_by_id[link_id]
		return None

	def get_avg_latency(self, link_id):
		prober = self.get_prober(link_id)
		if not prober:
			print '   ! WARNING: Prober not found.'
			return 0.0
		else:
			if prober.effective_ping == 0:
				return 0.0
		return prober.total_rtt / prober.effective_ping

	def get_packet_loss_percentage(self, link_id):
		prober = self.get_prober(link_id)
		if not prober:
			print '   ! WARNING: Prober not found.'
			return 0.0
		else:
			if prober.total_ping == 0:
				return 0.0
		return float(prober.ping_lost) / prober.total_ping * 100.0

	def kick_once(self):
		for p in self.prober_by_hwaddr.values():
			if not p.is_detecting():
				p.detect()

	def _handle_packet_in(self, event, pkt):
		if str(pkt.dst) in self.prober_by_hwaddr:
			prober = self.prober_by_hwaddr[str(pkt.dst)]
			if prober.switch1 == dpid_to_str(event.connection.dpid):
				prober._packet_in()
			if not prober.s_to_h and prober.switch2 == dpid_to_str(event.connection.dpid):
				prober._packet_in()

class Visualizer (object):
	_core_name = 'visualizer'
	def __init__(self):
		core.host_tracker.addListeners(self)
		core.openflow.addListeners(self)
		core.openflow_discovery.addListeners(self)
		self._t1 = Timer(SAMPLE_RATE, self._request_flow_stat, recurring = True)
		self._t2 = Timer(LOG_FREQUENCY, self._print_connectivity, recurring = True)
		self.hosts = set()
		self.switches = set()
		self.link_age = {}
		self.links = {}
		self.ports = {}
		self.bytes_last_sample = {}
		self.bytes_curr_sample = {}
		self.bytes_tot_sample = {}
		self.speed = {}
		self.source = {}
		self.target = {}
		self.link_id_assign = 0
		self.probemgr = QualityProbeManager()

	def _request_flow_stat(self):
		for c in core.openflow.connections:
			c.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
		for u in self.links:
			for v in self.links[u]:
				if u < v:
					id = self.links[u][v]
					s = 0.0
					if id in self.bytes_curr_sample:
						if id in self.bytes_last_sample:
							if self.bytes_curr_sample[id] > self.bytes_last_sample[id]:
								s = self.bytes_curr_sample[id] - self.bytes_last_sample[id]
							else:
								s = 0.0
						else:
							s = self.bytes_curr_sample[id]
						s /= SAMPLE_RATE
					self.speed[self.links[u][v]] = s
		self.bytes_last_sample = self.bytes_curr_sample
		self.bytes_curr_sample = {}
		# self.probemgr.kick_once()

	def _handle_PacketIn(self, event):
		packet = event.parsed
		if packet.type == packet.ARP_TYPE:
			self.probemgr._handle_packet_in(event, packet)

	def _handle_FlowStatsReceived(self, event):
		#print " # FlowStats received."
		#self.bytes_last_sample = self.bytes_curr_sample
		#self.bytes_curr_sample = {}

		s = dpid_to_str(event.connection.dpid)
		if s not in self.switches:
			print "WARNING: A wild router found."
			return

		for f in event.stats:
			if f.match.in_port != None and f.match.in_port in self.ports[s]:
				#print self.ports[s]
				hwsrc = self.ports[s][f.match.in_port]
			else:
				hwsrc = str(f.match.dl_src)
			hwdst = str(f.match.dl_dst)
			if hwsrc in self.links and s in self.links[hwsrc]:
				id = self.links[hwsrc][s];
				if id in self.bytes_curr_sample:
					self.bytes_curr_sample[id] += f.byte_count
				else:
					self.bytes_curr_sample[id] = f.byte_count
				if id in self.bytes_tot_sample:
					self.bytes_tot_sample[id] += f.byte_count
				else:
					self.bytes_tot_sample[id] = f.byte_count
			if hwdst in self.links[s]:
				id = self.links[s][hwdst]
				if id in self.bytes_curr_sample:
					self.bytes_curr_sample[id] += f.byte_count
				else:
					self.bytes_curr_sample[id] = f.byte_count
				if id in self.bytes_tot_sample:
					self.bytes_tot_sample[id] += f.byte_count
				else:
					self.bytes_tot_sample[id] = f.byte_count
		#self._print_connectivity();

	def _handle_ConnectionUp(self, event):
		print "openflow_ConnectionUp"

		s = str(dpid_to_str(event.dpid))
		print "Router %s has connected." % s
		if s not in self.switches:
			self.switches.add(s)
			self.links[s] = {}
			self.ports[s] = {}
			self.probemgr.update_table(self.hosts, self.switches)
		else:
			print "WARNING: Switch already exists."

	def _handle_ConnectionDown(self, event):
		#print "openflow.ConnectionDown"

		s = str(dpid_to_str(event.dpid))
		print "Router %s has disconnected." % s
		if s in self.switches:
			self.switches.remove(s)
			del self.links[s]
			del self.ports[s]
			self.probemgr.update_table(self.hosts, self.switches)
		else:
			print "WARNING: Switch does not exist."

	def _handle_LinkEvent(self, event):
		#print "openflow.discovery.LinkEvent"

		s1 = event.link.dpid1
		s2 = event.link.dpid2
		s1 = dpid_to_str(s1)
		s2 = dpid_to_str(s2)

		if s1 not in self.links:
			print "WARNING: Router %s not registered." % s1
			return
		if s2 not in self.links:
			print "WARNING: Router %s not registered." % s2
			return

		if event.added:
			if s2 not in self.links[s1] and s1 not in self.links[s2]:
				self.link_id_assign += 1
				link_id = self.link_id_assign
				self.links[s1][s2] = link_id
				self.links[s2][s1] = link_id
				self.ports[s1][event.link.port1] = s2
				self.ports[s2][event.link.port2] = s1
				self.speed[link_id] = 0.0
				self.probemgr.install(s1, event.link.port1, s2, event.link.port2, link_id)
				self.source[link_id] = s1
				self.target[link_id] = s2
				self.link_age[link_id] = time()
		elif event.removed:
			if s2 in self.links[s1]:
				link_id = self.links[s1][s2]
				if link_id in self.source:
					del self.source[link_id]
				if link_id in self.target:
					del self.target[link_id]
				self.probemgr.uninstall(link_id)
				if link_id in self.speed:
					del self.speed[link_id]
				if link_id in self.bytes_tot_sample:
					del self.bytes_tot_sample[link_id]
				del self.links[s1][s2]
				del self.links[s2][s1]
				del self.ports[s1][event.link.port1]
				del self.ports[s2][event.link.port2]
				if link_id in self.link_age:
					del self.link_age[link_id]

		# fork and do bandwidth test

	def _handle_HostEvent(self, event):
		print "host_tracker.HostEvent"

		h = str(event.entry.macaddr)
		s = str(dpid_to_str(event.entry.dpid))

		if event.leave:
			if h in self.hosts and s in self.switches:
				link_id = self.links[h][s]
				self.probemgr.uninstall(link_id)
				self.hosts.remove(h)
				if link_id in self.source:
					del self.source[link_id]
				if link_id in self.target:
					del self.target[link_id]
				if link_id in self.speed:
					del self.speed[link_id]
				if link_id in self.bytes_tot_sample:
					del self.bytes_tot_sample[link_id]
				del self.links[h]
				del self.links[s][h]
				del self.ports[s][event.entry.port]
				del self.ports[h]
				self.probemgr.update_table(self.hosts, self.switches)
				if link_id in self.link_age:
					del self.link_age[link_id]
			else:
				print "WARNING: Unknown host is disconnecting."
		else:
			if h not in self.hosts:
				if s in self.switches:
					self.link_id_assign += 1
					link_id = self.link_id_assign
					self.hosts.add(h)
					self.links[h] = {}
					self.links[s][h] = link_id
					self.links[h][s] = link_id
					self.ports[s][event.entry.port] = h
					self.ports[h] = {}
					self.ports[h][0] = s
					self.speed[link_id] = 0.0
					self.probemgr.update_table(self.hosts, self.switches)
					self.probemgr.install(s, event.entry.port, h, 0, link_id)
					self.source[link_id] = h
					self.target[link_id] = s
					self.link_age[link_id] = time()
				else:
					print "WARNING: Missing switch %s." % s

	def _print_connectivity(self):
		print " === current connectivity === "
		print " switch count	: %d" % len(self.switches)
		print " host count   	: %d" % len(self.hosts)
		print " active links 	:"
		for k in self.links.keys():
			for t in self.links[k].keys():
				if k < t:
					s = self.speed[self.links[k][t]]
					i = 0
					while s > 1024.0:
						s /= 1024.0
						i += 1
					print ' *', 'Switch' if k in self.switches else 'Host', k, '<-->', 'switch' if t in self.switches else 'host', t
					print '   + speed: %.2f' % s, SPEED_UNIT[i]
					print '   + average latency: %.3f' % self.probemgr.get_avg_latency(self.links[k][t]);
					print '   + packet loss: %.1f%%' % self.probemgr.get_packet_loss_percentage(self.links[k][t])
		print ""

def launch():
	print "Visualizer launching..."
	core.registerNew(Visualizer)
