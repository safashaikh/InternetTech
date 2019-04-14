# main libraries 
import binascii
import socket as syssock
import struct
import sys
import thread
import threading
import time
from numpy import random

# encryption libraries 
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame 
from inspect import currentframe, getframeinfo

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

firsttime = True
filelen_int = 0
num_packets = 0

SOCK352_SYN = 0x01 
SOCK352_FIN = 0x02 
SOCK352_ACK = 0x04 
SOCK352_RESET = 0x08 
SOCK352_HAS_OPT = 0xA0
WINDOW_SIZE = 4
TIMEOUT = 0.2
SLEEP_INTERVAL = 0.05
base = 0
lock = threading.Lock()

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

## init Timer with TIMEOUT = 0.2
send_timer = Timer(TIMEOUT)

class Packet:
	def __init__(self):
		'''
		___Flags__:
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
		self.header_len = struct.calcsize('!BBBBHHLLQQLL')	# 2 bytes
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
		#print ("Header Seq No is: "+str(self.seq_no)
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
		
# CS 352 project part 2 
# this is the initial socket library for project 2 
# You wil need to fill in the various methods in this
# library 

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages 
global sock352portTx
global sock352portRx
# the public and private keychains in hex format 
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
global ENCRYPT

publicKeysHex = {} 
privateKeysHex = {} 
publicKeys = {} 
privateKeys = {}

# this is 0xEC 
ENCRYPT = 236 

# this is the structure of the sock352 packet 
sock352HdrStructStr = '!BBBBHHLLQQLL'

def init(UDPportTx,UDPportRx):
	global sock352portTx
	global sock352portRx
	if (UDPportTx == ''):
		sock252portTx = int(UDPportRx)	
	if (UDPportRx == 0):
		sock352portRx = 27182
	else:
		sock352portRx = int(UDPportRx)
	if (UDPportTx == 0):
		sock352portTx = 27182
	else:
		sock352portTx = int(UDPportTx)	
    # create the sockets to send and receive UDP packets on 
    # if the ports are not equal, create two sockets, one for Tx and one for Rx

# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
	global publicKeysHex
	global privateKeysHex 
	global publicKeys
	global privateKeys 

	if (filename):
		try:
			keyfile_fd = open(filename,"r")
			for line in keyfile_fd:
				words = line.split()
				# check if a comment
				# more than 2 words, and the first word does not have a
				# hash, we may have a valid host/key pair in the keychain
				if ( (len(words) >= 4) and (words[0].find("#") == -1)):
					host = words[1]
					port = words[2]
					keyInHex = words[3]
					if (words[0] == "private"):
						privateKeysHex[(host,port)] = keyInHex
						privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
					elif (words[0] == "public"):
						publicKeysHex[(host,port)] = keyInHex
						publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
		except Exception,e:
			print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
	else:
			print ("error: No filename presented")             
	print("The public keys are: " + str(publicKeys.keys()))
	print("The private keys are: " + str(privateKeys.keys()))
	return (publicKeys,privateKeys)

class socket:

	def __init__(self):
		# create socket
		self.c_addr = None
		self.s_addr = None
		self.isserver = None
		self.udpPkt_hdr_data = struct.Struct('!BBBBHHLLQQLL')
		self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
		self.sock.setsockopt(syssock.SOL_SOCKET, syssock.SO_REUSEADDR, 1)
		#self.sock = mysocket()
		#self.sock.settimeout(10)
		self.connected = False
		self.encrypt = False
		self.publickey = None
		self.privatekey = None
		self.box = None
		self.nonce = None
		
	def bind(self,address):
		# bind to a port for server socket
		myhost, placeholder_port = address
		#print("This is my host: " + str(myhost))
		## server binds to its sock352portRx
		self.s_addr = (myhost, sock352portRx)
		print("S_addr is ")
		print(''+str(self.s_addr))
		## sets server sock flag
		self.isserver = True
		self.sock.bind(self.s_addr)
		return 

	def connect(self,*args):

		# example code to parse an argument list (use option arguments if you want)
		global sock352portTx
		global ENCRYPT
				
		# create conn from client perspective
		if (len(args) >= 1): 
			servhost,placeholder_port = args[0]
		if (len(args) >= 2):
			if (args[1] == ENCRYPT):
				self.encrypt = True
				
		## client calls connect, so c_addr is local and port is sock352portRx
		## s_addr is hostname and sock352portTx
		self.c_addr = ('localhost', sock352portRx)
		self.s_addr = (servhost, sock352portTx)
		## this is client
		self.isserver = False
		## bind to sock352portRx
		## bind to '' instead of localhost to receive over network
		self.sock.bind(('',sock352portRx))
			
		## initiate handshake
		P = Packet()
		P.flags = SOCK352_SYN ## set SYN bit
		SYN = P.pack_header()
		#print("CLIENT OG Seq # is:" +str(P.sequence_no))
		ack = 0
		Acked = False
		while not Acked:
			## send SYN message to server until Acked
			self.sock.sendto(SYN, self.s_addr)
			try:
				ack, serveraddr = self.sock.recvfrom(40)
				#print(ack)
				Acked = True
			except syssock.timeout:
				print ("Socket timeout")
				return
		## client received ACK, proceed to unpack
		SYNACK_header = self.udpPkt_hdr_data.unpack(ack)
		if(SYNACK_header[1]>>0 & 1 and SYNACK_header[1]>>2 & 1):
			#print ("SYN Segment Successfully Received" )
			## SYN bit success, send ACK message, SYN bit is 0
			P = Packet()
			P.flags = SOCK352_ACK ## set ACK
			P.ack_no = SYNACK_header[8] + 1 ## ACK NO is server seq_no + 1
			#print("server seq # is: "+str(SYNACK_header[8]))
			#print("Client seq no is: "+str(SYNACK_header[9]))
			P.sequence_no = SYNACK_header[9] ## client seq no is server ack = prev_client_seq_no + 1
			newACK = P.pack_header()
			self.sock.sendto(newACK, self.s_addr)
		# Error, SYN bit not set to 1
		else:
			print ("Error: SYN Segment Failed")
		
		## find public/private keys
		if(self.encrypt == True):
			# find public key using server's address
			host, port = self.s_addr
			port_str = str(port)
			hostname, aliaslist, iplist = syssock.gethostbyname_ex(host)
			myhost = syssock.gethostname()
			if myhost == hostname:
				aliaslist.append('localhost')
				iplist.append('127.0.0.1')
			print("server hostname is: "+str(hostname))
			print("server aliaslist is: "+str(aliaslist))
			print("server ip list is: "+str(iplist))
			found = False
			if (hostname,port_str) in publicKeys:
				self.publickey = publicKeys[(hostname, port_str)]
				found = True
				print("***key found as: "+hostname)
			if (found == False):
				for i in range(len(aliaslist)):
					if (aliaslist[i],port_str) in publicKeys:
						self.publickey = publicKeys[(aliaslist[i], port_str)]
						found = True
						print("***key found as: "+aliaslist[i])
						break
			if (found == False):
				for i in range(len(iplist)):
					if (iplist[i],port_str) in publicKeys:
						self.publickey = publicKeys[(iplist[i], port_str)]
						found = True
						print("***key found as: "+iplist[i])
						break
			# if no keys for the specific address, use wildcard public key
			if (found == False):
				if ('*','*') in publicKeys:
					self.publickey = publicKeys[('*','*')]
				# no suitable key found, continue w/o encryption
				else:
					print("Error: No public key found with port and host or wildcard, continue without encryption")
					self.encrypt = False
			
			
			'''
			found = False
			for i in range(len(tuple)):
				if ((tuple[i], str(port)) in publicKeys):
					self.publickey = publicKeys[(tuple[i], str(port))]
					found = True
					print("***key found as: "+tuple[i])
					break'''
			
			# find private key using client's own address
			host, port = self.c_addr
			port_str = str(port)
			hostname, aliaslist, iplist = syssock.gethostbyname_ex(host)
			myhost = syssock.gethostname()
			aliaslist.append(myhost)
			iplist.append(syssock.gethostbyname(myhost))
			print "client hostname is: ", hostname 
			print "client aliaslist is: ",aliaslist
			print "client ip list is: ", iplist
			found = False
			if (hostname,port_str) in privateKeys:
				self.privatekey = privateKeys[(hostname, port_str)]
				found = True
				print("***key found as: "+hostname)
			if (found == False):
				for i in range(len(aliaslist)):
					if (aliaslist[i],port_str) in privateKeys:
						self.privatekey = privateKeys[(aliaslist[i], port_str)]
						found = True
						print("***key found as: "+aliaslist[i])
						break
			if (found == False):
				for i in range(len(iplist)):
					if (iplist[i],port_str) in privateKeys:
						self.privatekey = privateKeys[(iplist[i], port_str)]
						found = True
						print("***key found as: "+iplist[i])
						break
			# if no keys for the specific address, use wildcard key
			if (found == False):
				if ('*','*') in privateKeys:
					self.privatekey = privateKeys[('*','*')]
				# no suitable key found, continue w/o encryption
				else:
					print("Error: No public key found with port and host or wildcard, continue without encryption")
					self.encrypt = False
				
		## if both keys are successfully found, create nonce and box object
		## only client needs to do nonce since client is the one encrypting
		print("Public key: " + str(self.publickey))
		print("Private key: " + str(self.privatekey))
		if (self.encrypt == True) and (self.publickey is not None) and (self.privatekey is not None):
			self.nonce = nacl.utils.random(Box.NONCE_SIZE)
			self.box = Box(self.privatekey, self.publickey)
		return 

	def listen(self,backlog):
		# listen is not used in this assignments 
		pass


	def accept(self,*args):
		# example code to parse an argument list (use option arguments if you want)
		global ENCRYPT
		if (len(args) >= 1):
			if (args[0] == ENCRYPT):
				self.encrypt = True
		# your code goes here 
		## create conn from server side 
		P = Packet()
		syn_buffer, clientaddr = self.sock.recvfrom(P.header_len) # wait for SYN segment
		self.c_addr = clientaddr
		header = self.udpPkt_hdr_data.unpack(syn_buffer)
		## Check SYN bit of packet
		if(header[1]>>0 & 1):
			#print ("SYN segment successfully received" )
			## SYN bit success, send SYNACK segment
			## header[8] = seq no
			P.ack_no = header[8] + 1
			P.flags = SOCK352_SYN + SOCK352_ACK
			#print("Client seq no is: ", header[8])
			P.sequence_no = random.randint(0xFFFFFFFF)
			#print("SERVER OG seq no is: "+str(P.sequence_no))
			SYNACK = P.pack_header()
			self.sock.sendto(SYNACK, self.c_addr)
			## wait for ACK from client
			syn_buffer = self.sock.recv(P.header_len)
			header = self.udpPkt_hdr_data.unpack(syn_buffer)
			## Check SYN bit is 0 and ACK bit is 1
			if(~(header[1]>>0 | 0)) and (header[1]>>2 & 1):
				print("Connection established" )
				#print("Client seq no is: ", header[8])
				clientsocket = self
				address = self.c_addr
			# Else, error with final ACK
			else:
				print("Error: SYN ACK from client failed")
		# Error, SYN bit not set to 1
		else:
			print ("Error: SYN Segment failed")	
		## find public/private keys
		if(self.encrypt == True):
			# find public key using client's address
			host, port = self.c_addr
			print "client host is",host
			port_str = str(port)
			hostname, aliaslist, iplist = syssock.gethostbyaddr(host)
			myhost = syssock.gethostname()
			if host == '127.0.0.1':
				aliaslist.append(myhost)
				iplist.append(syssock.gethostbyname(myhost))
				
			if myhost == hostname:
				aliaslist.append('localhost')
				iplist.append('127.0.0.1')
			print("client hostname is: "+str(hostname))
			print("client aliaslist is: "+str(aliaslist))
			print("client ip list is: "+str(iplist))
			found = False
			if (hostname,port_str) in publicKeys:
				self.publickey = publicKeys[(hostname, port_str)]
				found = True
				print("***key found as: "+hostname)
			if (found == False):
				for i in range(len(aliaslist)):
					if (aliaslist[i],port_str) in publicKeys:
						self.publickey = publicKeys[(aliaslist[i], port_str)]
						found = True
						print("***key found as: "+aliaslist[i])
						break
			if (found == False):
				for i in range(len(iplist)):
					if (iplist[i],port_str) in publicKeys:
						self.publickey = publicKeys[(iplist[i], port_str)]
						found = True
						print("***key found as: "+iplist[i])
						break
			# if no keys for the specific address, use wildcard public key
			if (found == False):
				if ('*','*') in publicKeys:
					self.publickey = publicKeys[('*','*')]
				# no suitable key found, continue w/o encryption
				else:
					print("Error: No public key found with port and host or wildcard, continue without encryption")
					self.encrypt = False
					
			# find private key using server's own address
			host, port = self.s_addr
			port_str = str(port)
			hostname, aliaslist, iplist = syssock.gethostbyname_ex('localhost')
			myhost = syssock.gethostname()
			aliaslist.append(myhost)
			iplist.append(syssock.gethostbyname(myhost))
			print("server hostname is: "+str(hostname))
			print("server aliaslist is: "+str(aliaslist))
			print("server ip list is: "+str(iplist))
			found = False
			if (hostname,port_str) in privateKeys:
				self.privatekey = privateKeys[(hostname, port_str)]
				found = True
				print("***key found as: "+hostname)
			if (found == False):
				for i in range(len(aliaslist)):
					if (aliaslist[i],port_str) in privateKeys:
						self.privatekey = privateKeys[(aliaslist[i], port_str)]
						found = True
						print("***key found as: "+aliaslist[i])
						break
			if (found == False):
				for i in range(len(iplist)):
					if (iplist[i],port_str) in privateKeys:
						self.privatekey = privateKeys[(iplist[i], port_str)]
						found = True
						print("***key found as: "+iplist[i])
						break
			# if no keys for the specific address, use wildcard key
			if (found == False):
				if ('*','*') in privateKeys:
					self.privatekey = privateKeys[('*','*')]
				# no suitable key found, continue w/o encryption
				else:
					print("Error: No public key found with port and host or wildcard, continue without encryption")
					self.encrypt = False
				
		## if both keys are successfully found, create box object
		print("Public key: " + str(self.publickey))
		print("Private key: " + str(self.privatekey))
		print("The client addr is: "+str(self.c_addr))
		if (self.encrypt == True) and (self.publickey is not None) and (self.privatekey is not None):
			self.box = Box(self.privatekey, self.publickey)
		return (clientsocket,address)

	def close(self):   # fill in your code here 
		# close conn if last packet recv, ELSE close vars
		if(self.isserver==False):
			## Client inits handshake, sends FIN bit
			P = Packet()
			P.flags = SOCK352_FIN
			CLIEND = P.pack_header()
			#self.sock.sendto(CLIEND, self.s_addr)
			sendack = False
			## Checks for ack or resends if timeout
			while not sendack:
				try:
					self.sock.sendto(CLIEND, self.s_addr)
					end_buffer = self.sock.recv(P.header_len)
					sendack = True
				except syssock.timeout:
					pass
			header = self.udpPkt_hdr_data.unpack(end_buffer)
			## Check that ACK bit is 1
			if(header[1]>>2 & 1):
				#print("Sever ACK received")
				## Waits for server FIN bit
				end_buffer = self.sock.recv(P.header_len)
				header = self.udpPkt_hdr_data.unpack(end_buffer)
				## Checks that FIN bit is 1
				if(header[1]>>1 & 1):
					## Sends ack to server
					P2 = Packet()
					P2.flags = SOCK352_ACK
					ENDACK = P2.pack_header()
					self.sock.sendto(ENDACK, self.s_addr)
					## Handshake complete
					print("Client connection has been terminated")
					self.sock.close()
				else:
					print("Error: Server term failed")
			else:
				print("Error ACK: Connection termination failed")
		else:
			## Server wait for FIN bit from client
			end_buffer = self.sock.recv(40)
			header = self.udpPkt_hdr_data.unpack(end_buffer)
			## Check that FIN bit is 1
			if(header[1]>>1 & 1):
				## Sends ACK to Client
				P = Packet()
				P.flags = SOCK352_ACK
				ENDACK = P.pack_header()
				self.sock.sendto(ENDACK, self.c_addr)
				## Sever sends FIN bit
				P2 = Packet()
				P2.flags = SOCK352_FIN
				SERVEND = P2.pack_header()
				#self.sock.sendto(SERVEND, self.c_addr)
				## Waits for ACK from client, resumbits if timeout
				sendack = False
				while not sendack:
					try:
						self.sock.sendto(SERVEND, self.c_addr)
						end_buffer = self.sock.recv(P.header_len)
						sendack = True
					except syssock.timeout:
						pass
				header = self.udpPkt_hdr_data.unpack(end_buffer)
				## Checks ACK bit is 1
				if(header[1]>>2 & 1):
					## Double handshake complete, end connection
					print("Server connection has been terminated")
					self.sock.close()
				else:
					print("Error: Second Ack from Client Failed")
			else:
				print("Error: Connection termination failed")

	# Receive thread

	def sender_receive(*client):
		global lock
		global base
		global send_timer
		global num_packets
		## extract client socket passed in
		sock = client[0].sock
		#print("num packets is "+str(num_packets))
		## while not all packets acknowledged
		while base < num_packets:
			## recv ACK with header size
			ack = sock.recv(40)
			ACK = client[0].udpPkt_hdr_data.unpack(ack)
			#print('Got ACK', ACK)
			## check if ACK bit set otw print error
			if (ACK[1]>>2 & 1):
				if ACK[9] > base:
					lock.acquire()
					base = ACK[9] # ack_no
					#print('Base updated', base)
					send_timer.stop()
					lock.release()
			else:
				print("Did not receive an ACK message")

	def send(self,buffer):
		# must do go back N
		# send length of file
		global firsttime
		global lock
		global base
		global send_timer
		global num_packets
		## first time send is called, we are simply sending file length
		if firsttime:
			self.sock.sendto(buffer, self.s_addr)
			#print("sent filesize"+str(buffer))
			firsttime = False
			return len(buffer)
		## Now sending packets
		if (firsttime == False):
			#print("Size of buffer: "+str(len(buffer)))
			## Divide buffer into segments of 64000-40; we subtract 40 because of packet header
			intnum = len(buffer) / (64000-40)
			num = len(buffer) / float(64000-40)
			if (self.encrypt == False):
				segments = [buffer[i:i+(64000-40)] for i in range(0,len(buffer),64000-40)]
			else:
				segments = [buffer[i:i+(64000-80)] for i in range(0,len(buffer),64000-80)]
			
			## Create individual packets from those segments
			packets = []
			for i in range(len(segments)):
				P = Packet()
				P.sequence_no = i
				# if encrypting, set option in header to 01 and encrypt payload
				if(self.encrypt == True):
					P.opt_ptr = 0x1
					segments[i] = self.box.encrypt(segments[i], self.nonce)
				packed_seg = P.pack_header_n_data(segments[i])
				packets.append(packed_seg)
			## Set arbitrary window size of 4
			window_size = set_window_size(4) #set_window_size(len(packets))
			## base - sequence_no of first segment in window
			## next_to_send = sequence_no of next segment not already sent
			## bytessent - bytes sent to server (not essential)
			## num_packets - global keeping track of total packets - needed for thread 2 as well
			next_to_send =0
			base = 0
			bytessent = 0
			num_packets = len(segments)
			
			## Start thread 2 to receive ACKs
			t2 = threading.Thread(target = self.sender_receive, args=(self,))
			t2.start()
			## while packets are still left
			while base < num_packets:
				lock.acquire()
				## Send all the packets in the window
				while next_to_send < base + window_size:
					#print('Sending packet', next_to_send)
					self.sock.sendto(packets[next_to_send], self.s_addr)
					if (self.encrypt == False):
						bytessent += len(segments[next_to_send])
 					else:
						bytessent += len(segments[next_to_send])-40
					next_to_send += 1
				## Start the timer
				if not send_timer.running():
					#print('Starting timer')
					send_timer.start()

				## Wait until a timer goes off or if we receive an ACK
				while send_timer.running() and not send_timer.timeout():
					lock.release()
					#print('Sleeping')
					time.sleep(SLEEP_INTERVAL)
					lock.acquire()

				if send_timer.timeout():
					## Timed out
					#print('Timeout')
					send_timer.stop()
					## if timed out, resend from base, which is the ack_no of last ack - indicating next segment to send
					next_to_send = base
				else:
					#print('Shifting window')
					window_size = set_window_size(num_packets)
				lock.release()
			
			## wait for last ack before closing
			t2.join()
			print("bytessent: "+str(bytessent))
			return bytessent 

	def recv(self,nbytes):
		# only accept expected packets
		# send acks
		# return # of bytes received
		# reassemble packets
		global firsttime
		#global filelen_int
		if firsttime:
			filelen = self.sock.recv(nbytes)
			#print(filelen)
			#longPacker = struct.Struct("!L")
			#filelen_int = longPacker.unpack(filelen)[0]
			#print("Received filesize: "+str(filelen_int))
			firsttime = False
			return filelen
		else:
			bytesrecv = 0
			recvfile = []
			expectedpack = 0
			while(bytesrecv < nbytes):
				packet = self.sock.recv(64000)
				if(packet is None):
					print("Empty packet")
				else:
					header = self.udpPkt_hdr_data.unpack_from(packet)
					#print(header)
					# check if seq no is expected seq no
					if(header[8]==expectedpack):
						#print("Expected = Recv Pack: "+str(expectedpack))
						# if it is, send ack where ack no = seq_no+1 and ack bit=1
						P = Packet()
						P.flags = SOCK352_ACK
						P.ack_no = header[8]+1
						PACKACK = P.pack_header()
						self.sock.sendto(PACKACK, self.c_addr)
						expectedpack = expectedpack + 1
						# keep track of how many bytes are recv
						datasize = header[11] #len(packet)-40
						bytesrecv += datasize
						#print("Total Bytes Recv: "+str(bytesrecv))
						#print("Datasize: "+str(datasize))
						# unpack data and append to list
						datafmt = '!'+str(datasize)+'s'
						segdata = struct.unpack_from(datafmt, packet, 40)
						mydata = segdata[0]
						# decrypt if encryption flag is set and options header is 01
						if (self.encrypt == True) and (header[2]==0x1):
							mydata = self.box.decrypt(segdata[0])
						recvfile.append(mydata)
					else:
						#print("Expected Pack: " + str(expectedpack) + "Recv Pack: "+str(header[8]))
						# if not, ignore packet and re-send last ack
						if(expectedpack!=0):
							P = Packet()
							P.flags = SOCK352_ACK
							P.ack_no = expectedpack 
							PACKACK = P.pack_header()
							self.sock.sendto(PACKACK, self.c_addr)
			# convert list to string and send
			str_recvfile = ''.join(recvfile)
			return str_recvfile



    


