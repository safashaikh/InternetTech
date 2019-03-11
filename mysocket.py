import binascii
import socket as syssock
import struct
import sys
from numpy import random
import signal

send_called = 0

class mysocket:
	def __init__(self):  # fill in your code here
		self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)

	def bind(self,address):
		return self.sock.bind(address)

	def sendto(self,buffer,address):  # fill in your code here
		global send_called
		if(send_called==5):
			send_called = 0
			#return None
		else:
			send_called = send_called + 1
			self.sock.sendto(buffer, address)

	def recvfrom(self,nbytes):
		return self.sock.recvfrom(nbytes)

	def recv(self,nbytes):
		return self.sock.recv(nbytes)

	def close(self):   # fill in your code here 
		return self.sock.close()

