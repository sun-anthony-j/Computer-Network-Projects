from sim.api import *
from sim.basics import *

'''
Create your RIP router in this file.
'''
class RIPRouter (Entity):
	def __init__(self):
		# Add your code here!
		# {DST1 : {Node1 : 3, Node2: 1, Node3: float("inf") }}

		self.forwarding_table = {}

		# {DST: Port}
		self.port_table = {}

	def handle_rx (self, packet, port):
		if (self is s1):
			print("\n")
			print('#'*20)
			self.log("I am " + str(self))
			self.log("Packet is " + str(packet))
			self.log("Port is " + str(port))
			self.log("My port_table is " + str(self.port_table))
			self.log("My forwarding_table is " + str(self.forwarding_table))
			self.log("This packet is type " + str(type(packet)))


		change = False

		if packet.src in self.forwarding_table and self.minimum_dist(packet.src) is float("inf"):
			return

		if isinstance(packet, Ping) and packet.dst == self:
			self.send(Pong(packet), port)

		elif isinstance(packet, DiscoveryPacket):
			if not packet.src in self.forwarding_table:
				self.forwarding_table[packet.src] = {}
			if packet.is_link_up:
					self.forwarding_table[packet.src][packet.src] = 1
					self.port_table[packet.src] = port
			else:
				print "Link went down"
				self.forwarding_table[packet.src][packet.src] = float("inf")
				self.port_table[packet.src] = None

			change = True

		elif isinstance(packet, RoutingUpdate):

			for node in packet.paths:

				if not node in self.forwarding_table:
					self.forwarding_table[node] = {}
					self.forwarding_table[node][packet.src] = packet.paths[node] + self.minimum_dist(packet.src)[1]
					change = True
				elif not packet.src in self.forwarding_table[node]:
					self.forwarding_table[node][packet.src] = packet.paths[node] + self.minimum_dist(packet.src)[1]
					change = True
				elif self.forwarding_table[node][packet.src] != (packet.paths[node] + self.minimum_dist(packet.src)[1]):
					self.forwarding_table[node][packet.src] = packet.paths[node] + self.minimum_dist(packet.src)[1]
					change = True

			# This code is BUGGED! Since we don't send information about ourselves, we cause other nodes to set the value
			# for us to a float inf! Fix!
			for dest in self.forwarding_table:
				if not dest in packet.paths and dest != packet.src:
					self.forwarding_table[dest][packet.src] = float("inf")
					change = True

		else:
			# Keep it, if it's for you
			if packet.dst is self:
				return
			else:
				#Pass it on the port determined by the forwarding table.
				next_step = self.minimum_dist(packet.dst)[0]
				if next_step in self.port_table:
					send_port = self.port_table[next_step]
					self.send(packet, send_port)

		if change is True:

			# For all of our B's
			for node in self.port_table:
				#doesn't send update back
				if isinstance(packet, DiscoveryPacket) or node is not packet.src:
					update_packet = RoutingUpdate()

					# For all of our C's
					for dest in self.forwarding_table:

						min_dist_pair = self.minimum_dist(dest)

						if self.forwarding_table[dest].keys():

							# Don't send to itself.
							if dest is not node:
								update_packet.add_destination(dest, min_dist_pair[1])
							#Poison reverse
							# If A's path to C goes thru B, omit C from update to B

								if min_dist_pair[0] is node:
									update_packet.add_destination(dest, float("inf"))
					#Send packet
					# self.log('Update sent from ' + str(self) + ' to ' +  str(node))
					self.send (update_packet, self.port_table[node])
		if (self is s1):
			self.log("My port_table is now " + str(self.port_table))
			self.log("My forwarding_table is now " + str(self.forwarding_table))
			self.log('End of my info')


	def minimum_dist(self, dest):

		f_table = self.forwarding_table[dest]

		min_key_val = (None, float("inf"))

		for node in f_table.keys():

			# self.log(str(node))

			# Find the min dist in the set
			if f_table[node] < min_key_val[1]:
				min_key_val = (node, f_table[node])

			# Break ties with the lowest port
			elif min_key_val[0]:
				if (f_table[node] == min_key_val[1]) and self.port_table[node] < self.port_table[min_key_val[0]]:
					min_key_val = (node, f_table[node])

		return min_key_val