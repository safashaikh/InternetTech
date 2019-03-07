import binascii
import socket as syssock
#import yoursocket # drops packets
import struct
import sys
from numpy import random
import signal

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

SOCK352_SYN = 0x01 
SOCK352_FIN = 0x02 
SOCK352_ACK = 0x04 
SOCK352_RESET = 0x08 
SOCK352_HAS_OPT = 0xA0

class Packet:
	def __init__(self):
		'''
		____Flags___:
		SOCK352_SYN 0x01 00000001 Connection initiation
		SOCK352_FIN 0x02 00000010 Connection end
		SOCK352_ACK 0x04 00000100 Acknowledgement #
		SOCK352_RESET 0x08 00001000 Reset the connection
		SOCK352_HAS_OPT 0xA0 00010000 Option field is valid
		'''
		self.version = 0x1 		# 1 byte
		self.flags = 0x1 		# 1 byte
		self.opt_ptr = 0		# 1 byte
		self.protocol = 0		# 1 byte
		if self.opt_ptr == 0:
			self.header_len = struct.calcsize('!BBBBHHLLQQLL')	# 2 bytes
		else:
			self.header_len = 0
		self.checksum = 0		# 2 bytes
		self.source_port = 0x00000000 # 4 bytes
		self.dest_port = 0x00000000 # 4 bytes
		self.sequence_no = random.randint(0xFFFFFFFF) # 8 bytes
		self.ack_no = 0x0000000000000000 # 8 bytes
		self.window = 0x00000000 # 4 bytes
		self.payload_len = 0x00000000 # 4 bytes
		self.header = None
		
			
	def pack_header(self):
		sock352PktHdrData = '!BBBBHHLLQQLL'
		udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
		self.header = udpPkt_hdr_data.pack(
			self.version, self.flags, self.opt_ptr,
			self.protocol, self.header_len, self.checksum, 
			self.source_port, self.dest_port, self.sequence_no, 
			self.ack_no, self.window, self.payload_len)
		return self.header
	
	def set_header_len(self,num):
		self.header_len = num
	
	def set_payload_len(self,num):
		self.payload_len = num
		

def init(UDPportTx,UDPportRx):   # initialize your UDP socket here
	#global sock
	global txport
	global rxport	
	if (UDPportTx == ''):
		txport = int(UDPportRx)	
	if (UDPportRx == 0):
		rxport = 27182
	else:
		rxport = int(UDPportRx)
	if (UDPportTx == 0):
		txport = 27182
	else:
		txport = int(UDPportTx)	

class socket:
	def __init__(self):  # fill in your code here
		# create socket
		self.c_addr = None
		self.s_addr = None
		self.isserver = None
		self.udpPkt_hdr_data = struct.Struct('!BBBBHHLLQQLL')
		self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
		#sock.settimeout(5)

	def bind(self,address):
		# bind to a port
		myhost, placeholder_port = address
		print("This is my host: " + str(myhost))
		self.s_addr = (myhost, rxport)
		self.isserver = True
		self.sock.bind(self.s_addr)
		return 

	def connect(self,address):  # fill in your code here
		# create conn from client perspective
		servhost, placeholder_port = address
		self.c_addr = ('', rxport)
		self.s_addr = (servhost, txport)
		self.isserver = False
		self.sock.bind(self.c_addr) 
		P = Packet()
		SYN = P.pack_header()
		print("CLIENT OG Seq # is:" +str(P.sequence_no))
		
		ack  = 0
		Acked = False
		while not Acked:
			self.sock.sendto(SYN, self.s_addr)
			try:
				ack, serveraddr = self.sock.recvfrom(40)
				print('test',ack)
				Acked = True
			except syssock.timeout:
				print ("Socket timeout")
				
		SYNACK_header = self.udpPkt_hdr_data.unpack(ack)
		if(SYNACK_header[1]>>0 & 1 and SYNACK_header[1]>>2 & 1):
			print ("SYN Segment Successfully Received" )
			# SYN bit success, send SYNACK segment
			P = Packet()
			P.flags = SOCK352_ACK
			P.ack_no = SYNACK_header[8] + 1
			print("server seq # is: "+str(SYNACK_header[8]))
			P.flags = SOCK352_ACK
			print("Client seq no is: ", SYNACK_header[9])
			P.sequence_no = SYNACK_header[9]
			SYNACK = P.pack_header()
			self.sock.sendto(SYNACK, self.s_addr)
		# Error, SYN bit not set to 1
		else:
			print ("Error: SYN Segment Failed")
		return 

	def listen(self,backlog):
		# do nothing
		# find size of socket array
		return

	def accept(self):
		# create conn from server side
		P = Packet()
		syn_buffer, clientaddr = self.sock.recvfrom(P.header_len) # wait for SYN segment
		self.c_addr = clientaddr
		header = self.udpPkt_hdr_data.unpack(syn_buffer)
		# Check SYN bit of packet
		if(header[1]>>0 & 1):
			print ("SYN segment successfully received" )
			# SYN bit success, send SYNACK segment
			P.ack_no = header[8] + 1
			P.flags = SOCK352_SYN + SOCK352_ACK
			print("Client seq no is: ", header[8])
			P.sequence_no = random.randint(0xFFFFFFFF)
			print("SERVER OG seq no is: ", P.sequence_no)
			SYNACK = P.pack_header()
			self.sock.sendto(SYNACK, self.c_addr)
			syn_buffer = self.sock.recv(P.header_len)
			header = self.udpPkt_hdr_data.unpack(syn_buffer)
			if(header[1]>>0 | 1) and (header[1]>>2 & 1):
				print("Connection established" )
				print("Client seq no is: ", header[8])
				clientsocket = self.sock
				address = self.c_addr
				return (clientsocket,address)
			else:
				print("Error: SYN ACK from client failed")
		# Error, SYN bit not set to 1
		else:
			print ("Error: SYN Segment failed")
		

	def close(self):   # fill in your code here 
		# close conn if last packet recv, ELSE close vars
		return 

	def send(self,buffer):
		'''def recvthread:
			while acks left:
				recv acks
				mark messages acked	'''
		# must do go back N
		# send length of file
		bytessent = 0     # fill in your code here
		return bytessent 

	def recv(self,nbytes):
		# only accept expected packets
		# send acks
		# return # of bytes received
		# reassemble packets
		bytesreceived = 0     # fill in your code 
		return bytesreceived 

