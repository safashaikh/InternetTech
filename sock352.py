import binascii
import socket as syssock
import struct
import sys
from numpy import random
import signal

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

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
			self.header_len = 40	# 2 bytes
		else:
			self.header_len = 0
		self.checksum = 0		# 2 bytes
		self.source_port = 0x00000000 # 4 bytes
		self.dest_port = 0x00000000 # 4 bytes
		self.sequence_no = random.randint(0xFFFFFFFFFFFFFFFF) # 8 bytes
		self.ack_no = 0x0000000000000000 # 8 bytes
		self.window = 0x00000000 # 4 bytes
		self.payload_len = 0x00000000 # 4 bytes
		
		sock352PktHdrData = '!BBBBHHLLQQLL'
		udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
		self.header = udpPkt_header_data.pack(
			self.version, self.flags, self.opt_ptr,
			self.protocol, self.header_len, self.checksum, 
			self.source_port, self.dest_port, self.sequence_no, 
			self.ack_no, self.window, self.payload_len)

def init(UDPportTx,UDPportRx):   # initialize your UDP socket here
	global sock
	global txport
	global rxport
	sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM) #create UDP socket	
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
		self.addr = None
		self.isserver = None
		return

	def bind(self,address):
		host, placeholder_port = address
		self.addr = (host, rxport)
		self.isserver = True
		sock.bind(self.addr)
		return 

	def connect(self,address):  # fill in your code here
		sock.isserver = False
		sock.bind(self.addr) 
		return 

	def listen(self,backlog):
		return

	def accept(self):
		return (clientsocket,address)

	def close(self):   # fill in your code here 
		return 

	def send(self,buffer):
		bytessent = 0     # fill in your code here
		return bytessent 

	def recv(self,nbytes):
		bytesreceived = 0     # fill in your code 
		return bytesreceived 

