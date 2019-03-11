import binascii
import socket as syssock
import struct
import sys
from numpy import random
import signal

recv_called = 0

class mysocket:
	def __init__(self):  # fill in your code here
		self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)

	def bind(self,address):
		return self.sock.bind(self.address)

	def sendto(self,buffer,address):  # fill in your code here
		return self.sock.sendto(buffer, address)

	def recvfrom(self,nbytes):
		return self.sock.recvfrom(nbytes)

	def recv(self,nbytes):
		global recv_called
		if(recv_called==5):
			recv_called = 0
			return None
		else:
			recv_called = recv_called + 1
			return self.sock.recv(nbytes)

	def close(self):   # fill in your code here 
		return self.sock.close()

