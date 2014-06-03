#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from struct import *
import sys, socket, re, string, time, random, email.parser

# TODO: Feel free to import any Python standard modules as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
	def __init__(self, config, timer, iface_int, iface_ext):
		self.timer = timer
		self.iface_int = iface_int
		self.iface_ext = iface_ext

		print("="*20)
		print("Start it up")

		# TODO: Load the firewall rules (from rule_filename) here.
		self.rules = []
		self.http_state = {}
		self.logging_mode = False
		self.testString = ''
		rules_handle = open(config['rule'])
		geoip_handle = open("geoipdb.txt")
		for file_line in rules_handle:
			line = " ".join(file_line.split())
			line = line.split(" ")
			line = [word.replace("\n", "") for word in line]
			if line[0] == 'drop' or line[0] == 'pass' or line[0] == 'deny' or line[0] == 'log':
				# DNS and HTTP
				if len(line) == 3:
					if (line[0]) == 'log':
						print 'Logging'
						self.logging_mode = True
					self.rules.append(Rule(line[0], line[1], line[2]))
				
				# Everything else
				else:
					self.rules.append(Rule(line[0], line[1], line[2], line[3], geoip_handle))
		print self.rules

		# TODO: Load the GeoIP DB ('geoipdb.txt') as well.

		# TODO: Also do some initialization if needed.
		self.loss_mode = False
		self.loss_rate = 0
		if 'loss' in config:
			self.loss_mode = True
			self.loss_rate = int(config['loss'])
			print "Running with loss"

	def handle_timer(self):
		# TODO: For the timer feature, refer to bypass.py
		pass

	# @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
	# @pkt: the actual data of the IPv4 packet (including IP header)
	def handle_packet(self, pkt_dir, pkt):
		# TODO: Your main firewall code will be here.
		try:
			packet = pkt

			IP_header = unpack('!BBHHHBBH4s4s' , packet[0:20])
			ver_IHL = IP_header[0]
			ver = ver_IHL >> 4
			IHL = ver_IHL & 0xF
			IP_header_length = IHL * 4

			protocol = IP_header[6]
			sender_addr = socket.inet_ntoa(IP_header[8]);
			destination_addr = socket.inet_ntoa(IP_header[9]);

			protocol_type = None
			transaction_complete = False
			drop_packet = False
			http_object = {}

			# TCP
			if protocol == 6: 
				TCP_header = unpack('!HHLLBBHHH' , packet[IP_header_length:IP_header_length+20])
				source_port = TCP_header[0]
				dest_port = TCP_header[1]
				seq_no = TCP_header[2]
				protocol_type = 'tcp'

				payload = len(packet[IP_header_length+20:])

				if dest_port == 80 or source_port == 80:

					# protocol_type = 'http'

					HTTP_header = packet[IP_header_length + 20:]

					if pkt_dir == PKT_DIR_OUTGOING:

						info = (sender_addr, destination_addr, source_port, dest_port)

						if info in self.http_state.keys():

							old_packet = self.http_state[info]

							if old_packet['next_seq_no'] == seq_no:
								old_packet['seq_no'] = seq_no
								old_packet['next_seq_no'] = seq_no + payload

								end_index_packet = HTTP_header.find('\r\n\r\n')
								
								if not old_packet['locked']:
									if end_index_packet != -1:
										old_packet['req'] += HTTP_header[:end_index_packet+4]
										old_packet['locked'] = True
									else:
										old_packet['req'] += HTTP_header
										# print old_packet

									end_index_so_far = old_packet['req'].find('\r\n\r\n')
									if end_index_so_far != -1:
										old_packet['locked'] = True
							else:
								if seq_no > old_packet['next_seq_no']:
									drop_packet = True

						else:
							new_pckt = {'addr+port': (sender_addr, destination_addr, source_port, dest_port), 'seq_no': seq_no, 'next_seq_no': seq_no + payload, 
							'locked': False, 'req': '', 'resp': '', 'completed': False, 'persistant': False}
							end_index_packet = HTTP_header.find('\r\n\r\n')
							if end_index_packet != -1:
								new_pckt['req'] += HTTP_header[:end_index_packet+4]
								new_pckt['locked'] = True
							else:
								new_pckt['req'] += HTTP_header
							self.http_state[(sender_addr, destination_addr, source_port, dest_port)] = new_pckt

					else:

						info = (destination_addr, sender_addr, dest_port, source_port)

						if info in self.http_state.keys():
							old_packet = self.http_state[info]
							if (old_packet['req'].find('\r\n\r\n') != -1):
								if old_packet['resp'] == '' or old_packet['next_seq_no'] == seq_no:
									old_packet['locked'] = False

									old_packet['seq_no'] = seq_no
									old_packet['next_seq_no'] = seq_no + payload

									end_index_packet = packet.find('\r\n\r\n')

									if not old_packet['locked']:
										if end_index_packet != -1:
											old_packet['resp'] += HTTP_header[:end_index_packet+4]
											old_packet['completed'] = True
											old_packet['locked'] = True
											transaction_complete = True
										else:
											old_packet['resp'] += HTTP_header

										end_index_so_far = old_packet['resp'].find('\r\n\r\n')
										if end_index_so_far != -1:
											old_packet['locked'] = True
											old_packet['completed'] = True
											transaction_complete = True
								else:
									if seq_no  > old_packet['seq_no']:
										drop_packet = True					
				
			# UDP
			if protocol == 17:
				UDP_header = unpack('!HHHH' , packet[IP_header_length:IP_header_length + 8])
				source_port = UDP_header[0]
				dest_port = UDP_header[1]

				UDP_length = UDP_header[2]
				UDP_checksum = UDP_header[3]
				protocol_type = 'udp'

				# DNS
				if dest_port == 53:
					DNS_header = unpack('!HHHHHH', packet[IP_header_length + 8:IP_header_length + 20])
					DNS_ID = DNS_header[0]
					# (1 << 15) + (OPCODE << 10) + (1 << 9)
					DNS_OPCODE = DNS_header[1] >> 10
					QDCOUNT = DNS_header[2]
					protocol_type = 'dns'
					if QDCOUNT == 1:
						QNAME=[]
						x = IP_header_length+20
						length_byte = unpack('!B', packet[x])[0]
						while length_byte != 0:
							fmt = '!' + str(length_byte) + 's'
							QNAME.append(unpack(fmt, packet[x + 1:x + length_byte + 1])[0])
							x += 1 + length_byte
							length_byte = unpack('!B', packet[x])[0]
						namelength = x - IP_header_length - 20 + 1
						DNS_NAME = unpack('!'+str(namelength)+'s', packet[IP_header_length+20:x+1])
						DNS_QTYPE = unpack('!H', packet[x + 1:x + 3])[0]
						DNS_QCLASS = unpack('!H', packet[x + 3:x+5])[0]
						DNS_QUESTION = packet[IP_header_length+20:x+5]
						QNAME = string.join(QNAME, ".")
			# ICMP
			if protocol == 1:
				ICMP_header = unpack('!BBHL' , packet[IP_header_length:IP_header_length + 8])
				ICMP_type = ICMP_header[0]
				protocol_type = 'icmp'
				dest_port = ICMP_type
				source_port = ICMP_type


			match = None
			ip_addr = None
			port = None

			if pkt_dir == PKT_DIR_INCOMING:
				port = source_port
				ip_addr = sender_addr
			else:
				port = dest_port
				ip_addr = destination_addr

			if not self.loss_mode or not self.loss_simulation(self.loss_rate):

				for rule in self.rules:

					if protocol_type == rule.storage['protocol'] or rule.storage['protocol'] == 'http':
						if rule.storage['protocol'] == 'dns':
							if rule.match(QNAME):
								match = rule
							else:
								# PASS
								if not match:
									match = "PASS"
						else:
							if rule.storage['protocol'] == 'http' and transaction_complete:
								# print "HTTP"
								key = (destination_addr, sender_addr, dest_port, source_port)
								transaction = self.http_state[key]
								http_object = http_parse(transaction)
								print http_object
								if rule.match(http_object['host']):
									f = open('http.log', 'a')
									wri = http_object['host'] + ' ' + http_object['method'] + ' ' + http_object['path'] + ' ' \
									+ http_object['version'] + ' ' + http_object['status_code'] + ' ' + http_object['object_size'] + '\n'
									# print wri
									f.write(wri)

									f.flush()
									# raise Exception
									if not self.http_state[key]['persistant']:
										del self.http_state[key]
									else:
										transaction['resp'] = ''
										transaction['req'] = ''
										transaction['completed'] = False
										transaction['locked'] = False
									transaction_complete = True
							
							if rule.storage['protocol'] == 'tcp':

								if rule.match(ip_addr) and rule.portMatch(port):
									match = rule
								else:
									if not match:
										match = "PASS"

			# print match
			if not match or match == "PASS" or match.storage['verdict'] == 'pass' or not drop_packet:	
				if pkt_dir == PKT_DIR_INCOMING:
					self.iface_int.send_ip_packet(pkt)
				elif pkt_dir == PKT_DIR_OUTGOING:
					self.iface_ext.send_ip_packet(pkt)
			elif match.storage['verdict'] == 'deny':
				resp_pkt = None
				if match.storage['protocol'] == 'tcp':
					# DROP PACKET AND RESPOND WITH RST
					resp_pkt = create_tcp_deny(sender_addr, destination_addr, source_port,dest_port)
				elif match.storage['protocol'] == 'dns':
					if pkt_dir == PKT_DIR_OUTGOING:
					# Drop packet and respond with placeholder redirect
					# DNS_ID, OPCODE, NAME, namelength, dest_addr, src_addr
						if DNS_QTYPE != 'AAAA':
							resp_pkt = create_dns_deny(DNS_ID, DNS_OPCODE, DNS_NAME[0], namelength, destination_addr, sender_addr, source_port, DNS_QUESTION)
					else:
						resp_pkt = packet
				# print resp_pkt
				if pkt_dir == PKT_DIR_INCOMING:
					self.iface_ext.send_ip_packet(resp_pkt)
				elif pkt_dir == PKT_DIR_OUTGOING:
					self.iface_int.send_ip_packet(resp_pkt)




		# END Try
		except Exception as e:
			raise e
			if pkt_dir == PKT_DIR_INCOMING:
				self.iface_int.send_ip_packet(pkt)
			elif pkt_dir == PKT_DIR_OUTGOING:
				self.iface_ext.send_ip_packet(pkt)


	# TODO: You can add more methods as you want.

	def loss_simulation(self, rate):
		chance = float(float(rate)/float(100))
		r_v = random.random()
		if r_v <= chance:
			return True
		return False


	def link_bandwidth_limit():
		pass
# END Firewall

# TODO: You may want to add more classes/functions as well.
def create_tcp_deny(src_addr, dest_addr, src_port, dest_port):
	#TCP header
	tcp_source = dest_port
	tcp_dest = src_port
	seqno = 0
	ackno = 0
	tcpflags = (1 << 2) + (5 << 12)
	window = 1
	checksum = 0
	urg = 0
	# tcp = [tcp_source, tcp_dest, seqno, ackno, tcpflags, window, checksum, urg]
	tcp_packed = pack('!HHLLHHHH' , tcp_source, tcp_dest, seqno, ackno, tcpflags, window, checksum, urg)
	checksum = make_tcp_checksum (tcp_packed, src_addr, dest_addr)
	# tcp = [tcp_source, tcp_dest, seqno, ackno, tcpflags, window, checksum, urg]
	tcp_packed = pack('!HHLLHHHH' , tcp_source, tcp_dest, seqno, ackno, tcpflags, window, checksum, urg)

	#IP header
	versionIHL = ((4 << 4) + 5)
	TOS = 0
	#check length later
	Length = 40
	ID = 0
	Flags = 0
	TTL = 1
	protocol = 6
	checksum = 0
	IP_source = socket.inet_aton(dest_addr)
	IP_dest = socket.inet_aton(src_addr)
	# IP_header = [versionIHL, TOS, Length, ID, Flags, TTL, protocol, checksum, IP_source, IP_dest]
	IP_header_packed = pack ('!BBHHHBBH4s4s', versionIHL, TOS, Length, ID, Flags, TTL, protocol, checksum, IP_source, IP_dest)
	checksum = make_ip4_checksum (IP_header_packed)
	# IP_header = [versionIHL, TOS, Length, ID, Flags, TTL, protocol, checksum, IP_source, IP_dest]
	IP_header_packed = pack ('!BBHHHBBH4s4s', versionIHL, TOS, Length, ID, Flags, TTL, protocol, checksum, IP_source, IP_dest)

	return IP_header_packed + tcp_packed

def create_dns_deny (DNS_ID, OPCODE, NAME, namelength, dest_addr, src_addr, src_port, question):
	#DNS header
	DNS_flags = (1 << 15) + (OPCODE << 10) + (1 << 10)
	QDCOUNT = 1
	ANCOUNT = 1
	NSCOUNT = 0
	ARCOUNT = 0
	DNS_header = pack('!HHHHHH', DNS_ID, DNS_flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
	#DNS Question

	#DNS Answer
	TYPE = 1
	CLASS = 1
	TTL = 1
	RDLENGTH = 4
	RDATA = socket.inet_aton('169.229.49.109')
	#type=H,class= H, TTL = L, RDLENGTH = H, RDATA = 4s
	DNS = pack('!'+str(namelength)+'sHHLH4s', NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA)
	DNS_length = len(DNS)+len(DNS_header)+len(question)

	#UDP header
	UDP_src_port = 53
	UDP_dest_port = src_port
	UDP_length = 8 + DNS_length
	UDP_checksum = 0
	UDP = pack ('!HHHH', UDP_src_port, UDP_dest_port, UDP_length, UDP_checksum)

	#IP header
	versionIHL = ((4 << 4) + 5)
	TOS = 0
	#check length later
	Length = 20 + UDP_length
	ID = 0
	Flags = 0
	TTL = 1
	protocol = 17
	checksum = 0
	IP_source = socket.inet_aton(dest_addr)
	IP_dest = socket.inet_aton(src_addr)
	IP_header_packed = pack ('!BBHHHBBH4s4s', versionIHL, TOS, Length, ID, Flags, TTL, protocol, checksum, IP_source, IP_dest)
	checksum = make_ip4_checksum (IP_header_packed)
	# IP_header = [versionIHL, TOS, Length, ID, Flags, TTL, protocol, checksum, IP_source, IP_dest]
	IP_header_packed = pack ('!BBHHHBBH4s4s', versionIHL, TOS, Length, ID, Flags, TTL, protocol, checksum, IP_source, IP_dest)

	return IP_header_packed + UDP + DNS_header + question + DNS 


# Returns a dictionary corresponding to the correct http object
def http_parse(message):
	packet = message['req'] + '=RESP=' + message['resp']
	potential_methods = ['GET', 'POST', 'PUT', 'DROP']
	http_obj = {}

	# HOSTNAME
	# METHOD
	# PATH
	# VERSION
	for method in potential_methods:
		if packet.find(method) >= 0:
			break

	http_section = packet[packet.find(method):].split(' ')
	http_obj['method'] = method
	http_obj['path'] = http_section[1]
	http_obj['version'] = http_section[2].split('\r')[0]
	host_index = packet.find("Host:")
	if host_index == -1:
		http_obj['host'] = destination_addr
	else:
		http_obj['host'] = packet[packet.find("Host:"):].split(" ")[1].split('\r')[0]
	cont_index = (packet.find('Content-Length'), packet.find('content-length'))
	if max(cont_index) == -1:
		http_obj['object_size'] = "-1"
	else:
		http_obj['object_size'] = packet[max(cont_index):].split(" ")[1].split('\r')[0]
	http_obj['status_code'] = packet[packet.find('=RESP='):].split(" ")[1] 
	# OBJECT_SIZE
	return http_obj


def make_tcp_checksum (input, src_addr, dest_addr):
	#Assumes protocol is always 6
	#Assumes input,src_addr,dest_addr are in packed binary
	#pad tcp segment if byte count is odd
	length=len(input)
	if length%2 == 1:
		input= input << 8
	sum = 0
	for index in range(0, len(input), 2):
		sum = one_complement_add(sum, unpack('!H', input[index]+input[index+1])[0] )

	sum = one_complement_add(sum, unpack('!H', src_addr[0:2])[0])
	sum = one_complement_add(sum, unpack('!H', src_addr[2:4])[0])
	sum = one_complement_add(sum, unpack('!H', dest_addr[0:2])[0])
	sum = one_complement_add(sum, unpack('!H', dest_addr[2:4])[0])
	sum = one_complement_add(sum, 0x0006)
	sum = one_complement_add(sum, length)

	return ~sum & 0xffff

def make_ip4_checksum (input):
	#Assumes input is in packed binary
	sum = 0 
	for index in range(0, len(input), 2):
		#sum = one_complement_add((ord(input[index]) + (ord(input[index + 1]) << 8)), sum)
		sum = one_complement_add(sum, unpack('!H', input[index:index+2])[0] )
	return ~sum & 0xffff

def one_complement_add (x, y):
	return ((x + y) & 0xffff) + ((x + y) >> 16)

class Rule:

	def __init__(self, verdict, protocol, ipOrDomain, port=None, geodb=None):
		self.storage = {}
		self.storage['verdict'] = verdict

		protocol = protocol.lower()
		self.storage['protocol'] = protocol

		if protocol == 'dns':
			self.storage['domain'] = ipOrDomain
			self.storage['port'] = {'val': port, 'class': 'SINGLE'}

			# any
			if ipOrDomain.find("*") != -1:
				self.storage['dns'] = {'val': ipOrDomain, 'class': 'ANY'}

				def wc_match(l1, l2):
					match = False
					split_list1 = l1.split(".")
					split_list2 = l2.split(".")
					split_list1.reverse()
					split_list2.reverse()
					for i in range(len(split_list1)):
						if split_list1[i] == split_list2[i]:
							match = True
						elif split_list2[i] == "*" and len(split_list1) >= len(split_list2):
							match = True
							break
						else:
							match = False
							break
					return match

				def wild_card_match(l):
					return wc_match(l, ipOrDomain)

				self.match = wild_card_match

			# specific
			else:
				self.storage['dns'] = {'val': ipOrDomain, 'class': 'SINGLE'}
				self.match = lambda x: x.split(".") == ipOrDomain.split(".")

		# Not DNS based
		elif protocol == 'http':
			self.storage['http'] = {'val': ipOrDomain, 'class': None}

			def wc_match(l1, l2):
				match = False
				split_list1 = l1.split(".")
				split_list2 = l2.split(".")
				split_list1.reverse()
				split_list2.reverse()
				for i in range(len(split_list1)):
					if split_list1[i] == split_list2[i]:
						match = True
					elif split_list2[i] == "*" and len(split_list1) >= len(split_list2):
						match = True
						break
					else:
						match = False
						break
				return match

			def wild_card_match(l):
				return wc_match(l, ipOrDomain)

			def matcher(val):
				if ipOrDomain == '*':
					self.storage['http']['class'] = 'ANY'
					return True
				elif ipOrDomain[0].isdigit():
					self.storage['http']['class'] = 'IP'
					return val == ipOrDomain or val == 'EXTERNAL_MATCH'
				else:
					self.storage['http']['class'] = 'DOMAIN'
					return wild_card_match(val)

			self.match = matcher

		else:
			self.storage['ip'] = {'val': ipOrDomain, 'class': None}

			# any

			if ipOrDomain == 'any':
				self.storage['ip']['class'] = 'ANY'
				self.match = lambda x: True
			# Country code
			elif len(ipOrDomain) == 2:
				regex = '.+'+ipOrDomain.upper()
				matches = []
				for line in geodb:
					match = re.findall(regex, line)
					if match != []:
						match = match[0].split(" ")
						first_ip = unpack('!L',socket.inet_aton(match[0]))[0]
						second_ip = unpack('!L',socket.inet_aton(match[1]))[0]
						# Makes the IPs as a range object in memory
						matches.append((first_ip, second_ip))

				def geo_db_matches(ip):
					long_ip = unpack('!L',socket.inet_aton(ip))[0]
					for val in matches:
						if long_ip >= val[0] and long_ip <= val[1]:
							return True
					return False

				self.storage['ip']['class'] = 'COUNTRY CODE'
				self.match = geo_db_matches
				
			# Prefix
			elif ipOrDomain.find('/') != -1:
				self.storage['ip']['class'] = 'PREFIX'
				prefix_num = int(ipOrDomain.split("/")[1])
					
				def binstring (ipstring):
					splitip = ipstring.split('.')
					bin_ip = [0,1,2,3]
					bin_ip[0] = bin(int(splitip[0]))
					bin_ip[1] = bin(int(splitip[1]))
					bin_ip[2] = bin(int(splitip[2]))
					bin_ip[3] = bin(int(splitip[3]))
					bin_ip[0] = bin_ip[0][2:]
					bin_ip[1] = bin_ip[1][2:]
					bin_ip[2] = bin_ip[2][2:]
					bin_ip[3] = bin_ip[3][2:]
					for x in range(0,4):
							while len(bin_ip[x]) < 8:
									bin_ip[x] = '0' + bin_ip[x]
					return bin_ip[0] + bin_ip[1] + bin_ip[2] + bin_ip[3]

				def pref_match(ip):
					raw_ip = binstring(ip)
					match_raw = binstring(ipOrDomain.split("/")[0])[0:prefix_num]
					slice_ip = raw_ip[0:prefix_num]
					return match_raw == slice_ip
				
				self.match = pref_match

			# Single IP
			else:
				self.storage['ip']['class'] = 'SINGLE'
				self.match = lambda x: x == self.storage['ip']['val']


			self.storage['port'] = {'val': port, 'class': None}

			# any

			if port == 'any':

				self.storage['port']['class'] = 'ANY'
				self.portMatch = lambda x: True

			# range

			elif len(port.split("-")) == 2:
				self.storage['port']['class'] = 'RANGE'
				self.portMatch = lambda x: int(x) in range(int(port.split("-")[0]), int(port.split("-")[1] + 1))

			# Single port
			else:
				self.storage['port']['class'] = 'SINGLE'
				self.portMatch = lambda x: int(x) == int(port)

		# END else
	# END __init__

	def __str__(self):
		return str(self.storage)
	def __repr__(self):
		return self.__str__()
# END Rule