import binascii
import socket as syssock
#import yoursocket # drops packets
import struct
import sys
#import _thread
import time
from numpy import random


# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

firsttime = True
filelen_int = 0

SOCK352_SYN = 0x01 
SOCK352_FIN = 0x02 
SOCK352_ACK = 0x04 
SOCK352_RESET = 0x08 
SOCK352_HAS_OPT = 0xA0
WINDOW_SIZE = 4
TIMEOUT = 0.2
base = 0
#lock = _thread.allocate_lock()
#send_timer = Timer(TIMEOUT)

def set_window_size(num_packets):
	global base
	return min(WINDOW_SIZE, num_packets - base)


class Timer(object):
	TIMER_STOP = -1

	def __init__(self, duration):
		self._start_time = self.TIMER_STOP
		self._duration = duration

	# Starts the timer
	def start(self):
		if self._start_time == self.TIMER_STOP:
			self._start_time = time.time()

	# Stops the timer
	def stop(self):
		if self._start_time != self.TIMER_STOP:
			self._start_time = self.TIMER_STOP

	# Determines whether the timer is runnning
	def running(self):
		return self._start_time != self.TIMER_STOP

	# Determines whether the timer timed out
	def timeout(self):
		if not self.running():
			return False
		else:
			return time.time() - self._start_time >= self._duration

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
		self.flags = 0 		# 1 byte
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
		self.data = None
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
		
	def pack_header_n_data(self,data):
		self.data = data #list(bytearray(data,'utf-8'))
		self.payload_len = len(self.data)
		#print("payload len is:"+str(self.payload_len))
		packstr = '!BBBBHHLLQQLL'
		packstr+= str(self.payload_len)+'s'
		packstruct = struct.Struct(packstr)
		packed_seg = packstruct.pack(
			self.version, self.flags, self.opt_ptr,
			self.protocol, self.header_len, self.checksum, 
			self.source_port, self.dest_port, self.sequence_no, 
			self.ack_no, self.window, self.payload_len,self.data)
		return packed_seg
		

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
		P.flags = SOCK352_SYN
		SYN = P.pack_header()
		#print("CLIENT OG Seq # is:" +str(P.sequence_no))
		
		ack  = 0
		Acked = False
		while not Acked:
			self.sock.sendto(SYN, self.s_addr)
			try:
				ack, serveraddr = self.sock.recvfrom(40)
				print(ack)
				Acked = True
			except syssock.timeout:
				print ("Socket timeout")
				return
				
		SYNACK_header = self.udpPkt_hdr_data.unpack(ack)
		if(SYNACK_header[1]>>0 & 1 and SYNACK_header[1]>>2 & 1):
			print ("SYN Segment Successfully Received" )
			# SYN bit success, send SYNACK segment
			P = Packet()
			P.flags = SOCK352_ACK
			P.ack_no = SYNACK_header[8] + 1
			#print("server seq # is: "+str(SYNACK_header[8]))
			P.flags = SOCK352_ACK
			#print("Client seq no is: "+str(SYNACK_header[9]))
			P.sequence_no = SYNACK_header[9]
			newACK = P.pack_header()
			self.sock.sendto(newACK, self.s_addr)
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
			#print("Client seq no is: ", header[8])
			P.sequence_no = random.randint(0xFFFFFFFF)
			#print("SERVER OG seq no is: "+str(P.sequence_no))
			SYNACK = P.pack_header()
			self.sock.sendto(SYNACK, self.c_addr)
			syn_buffer = self.sock.recv(P.header_len)
			header = self.udpPkt_hdr_data.unpack(syn_buffer)
			if(~(header[1]>>0 | 0)) and (header[1]>>2 & 1):
				print("Connection established" )
				#print("Client seq no is: ", header[8])
				clientsocket = self
				address = self.c_addr
				return (clientsocket,address)
			else:
				print("Error: SYN ACK from client failed")
		# Error, SYN bit not set to 1
		else:
			print ("Error: SYN Segment failed")
		

	def close(self):   # fill in your code here 
		# close conn if last packet recv, ELSE close vars
		if(self.isserver==False):
			# Client inits handshake, sends FIN bit
			P = Packet()
			P.flags = SOCK352_FIN
			CLIEND = P.pack_header()
			#self.sock.sendto(CLIEND, self.s_addr)
			sendack = False
			# Checks for ack or resends if timeout
			while not sendack:
				try:
					self.sock.sendto(CLIEND, self.s_addr)
					end_buffer = self.sock.recv(P.header_len)
					sendack = True
				except syssock.timeout:
					pass
			header = self.udpPkt_hdr_data.unpack(end_buffer)
			# Check that ACK bit is 1
			if(header[1]>>2 & 1):
				print("Sever ACK received")
				# Waits for server FIN bit
				end_buffer = self.sock.recv(P.header_len)
				header = self.udpPkt_hdr_data.unpack(end_buffer)
				# Checks that FIN bit is 1
				if(header[1]>>1 & 1):
					# Sends ack to server
					P.flags = SOCK352_ACK
					ENDACK = P.pack_header()
					self.sock.sendto(ENDACK, self.s_addr)
					# Handshake complete
					print("Client connection has been terminated")
					self.sock.close()
				else:
					print("Error: Server term failed")
			else:
				print("Error ACK: Connection termination failed")
		else:
			# Server wait for FIN bit from client
			P = Packet()
			end_buffer = self.sock.recv(P.header_len)
			header = self.udpPkt_hdr_data.unpack(end_buffer)
			# Check that FIN bit is 1
			if(header[1]>>1 & 1):
				# Sends ACK to Client
				P.flags = SOCK352_ACK
				ENDACK = P.pack_header()
				self.sock.sendto(ENDACK, self.c_addr)
				# Sever sends FIN bit
				P.flags = SOCK352_FIN
				SERVEND = P.pack_header()
				#self.sock.sendto(SERVEND, self.c_addr)
				# Waits for ACK from client, resumbits if timeout
				sendack = False
				while not sendack:
					try:
						self.sock.sendto(SERVEND, self.c_addr)
						end_buffer = self.sock.recv(P.header_len)
						sendack = True
					except syssock.timeout:
						pass
				header = self.udpPkt_hdr_data.unpack(end_buffer)
				# Checks ACK bit is 1
				if(header[1]>>2 & 1):
					# Double handshake complete, end connection
					print("Server connection has been terminated")
					self.sock.close()
				else:
					print("Error: Second Ack from Client Failed")
			else:
				print("Error: Connection termination failed")

	def send(self,buffer):
		'''def recvthread:
			while acks left:
				recv acks
				mark messages acked	'''
		# must do go back N
		# send length of file
		global firsttime
		global lock
		global base
		global send_timer
		#print("buffer length is: "+str(len(buffer)))
		if firsttime:
			self.sock.sendto(buffer, self.s_addr)
			print("sent filesize")
			firsttime = False
			return 0
		else :
			print("Size of buffer: "+str(len(buffer)))
			print("Size of buffer (sys): "+str(sys.getsizeof(buffer)))
			intnum = len(buffer) / (64000-40)
			num = len(buffer) / float(64000-40)
			segments = [buffer[i:i+(64000-40)] for i in range(0,intnum,64000-40)]
			if num>intnum :
				seg = buffer[((64000-40)*intnum):]
				segments.append(seg)
				intnum += 1
			packets = []
			for i in range(len(segments)):
				P = Packet()
				packed_seg = P.pack_header_n_data(segments[i])
				packets.append(packed_seg)
			'''
			print("Num segments is: "+str(len(segments)))
			for i in range(len(segments)):
				print(len(segments[i]))'''
			window_size = set_window_size(len(packets))
			next_to_send =0
			base = 0
			bytessent = 0
			
			# Start the receiver thread
			_thread.start_new_thread(sender_receive, (self.sock,))

			
			while base < num_packets:
				lock.acquire()
				# Send all the packets in the window
				while next_to_send < base + window_size:
					print('Sending packet', next_to_send)
					self.sock.sendto(packets[next_to_send], self.s_addr)
					bytessent += len(segments[next_to_send]) 
					next_to_send += 1

				# Start the timer
				if not send_timer.running():
					print('Starting timer')
					send_timer.start()

				# Wait until a timer goes off or we get an ACK
				while send_timer.running() and not send_timer.timeout():
					lock.release()
					print('Sleeping')
					time.sleep(SLEEP_INTERVAL)
					lock.acquire()

				if send_timer.timeout():
					# Looks like we timed out
					print('Timeout')
					send_timer.stop()
					next_to_send = base
				else:
					print('Shifting window')
					window_size = set_window_size(num_packets)
				lock.release()
			'''	
			j = 0
			while(bytessent < len(buffer)):
				print(j)
				self.sock.sendto(packets[j], self.s_addr)
				bytessent += len(segments[j]) 
				print("Seg size: "+str(len(segments[j]) ))
				print("Bytes sent = "+str(bytessent))
				j = j+ 1
				# fill in your code here
			'''
			return bytessent 
			
	# Receive thread
	def sender_receive(sock):
		global lock
		global base
		global send_timer

		while True:
			ack = self.sock.recv(40)
			ACK = self.udpPkt_hdr_data.unpack(ack)
			print('Got ACK', ACK)
			if (ACK[1]>>2 && 1):
				if ACK[9] > base:
					lock.acquire()
					base = ACK[9] # ack_no
					print('Base updated', base)
					send_timer.stop()
					lock.release()
			else:
				print("Did not receive an ACK message")

	def recv(self,nbytes):
		# only accept expected packets
		# send acks
		# return # of bytes received
		# reassemble packets
		global firsttime
		global filelen_int
		if firsttime:
			filelen = self.sock.recv(nbytes)
			longPacker = struct.Struct("!L")
    			filelen_int = longPacker.unpack(filelen)[0]
			print("Received filesize: "+str(filelen_int))
			firsttime = False
			return filelen
		else:
			if(filelen_int == 0):
				print("Error: Filelen = 0")
				pass
			#intnum = filelen_int / (64000-40)
			#num = filelen_int / float(64000-40)
			#smallLastPack = False
			#lastPack = 0
			#if (num > intnum):
			#	smallLastPack = True
			#	lastPack = filelen_int - intnum*(64000-40)
			bytesrecv = 0
			recvfile = []
			while(bytesrecv < filelen_int):
				'''if(filelen_int-bytesrecv < 64000):
					lastPack = filelen_int-bytesrecv
					packet = self.sock.recv(lastPack)
					bytesrecv = bytesrecv + lastPack
				else:
					packet = self.sock.recv(64000)
					bytesrecv = bytesrecv + len(packet)-40'''
				packet = self.sock.recv(64000)
				header = self.udpPkt_hdr_data.unpack_from(packet)
				datasize = header[11] #len(packet)-40
				bytesrecv += datasize
				print("Total Bytes Recv: "+str(bytesrecv))
				print("Datasize: "+str(datasize))
				datafmt = '!'+str(datasize)+'s'
				segdata = struct.unpack_from(datafmt, packet, 40)
				recvfile.append(segdata[0])
			str_recvfile = ''.join(recvfile)
			return str_recvfile
				

