from pwnlib.logger       import log
from pwnlib.utils.colors import green
from pwnlib.utils.misc   import hexdump

class tube(object):
	"""abstract class for tubes"""
	def interactive(self):
		pass
	
	def close(self):
		pass

	def recv(self, size, nolog=False):
		pass

	def send(self, data, nolog=False):
		pass

	def recvuntil(self, delim):
		data = self.recv(len(delim), nolog=True)
		while data[-len(delim):]!=delim:
			data += self.recv(1, nolog=True)
		log.debug("Received {} bytes\n{}".format(green(len(data)), hexdump(data)))
		return data

	def recvline(self):
		return self.recvuntil(b"\n")

	def recvall(self):
		data = b""
		try:
			while True:
				data += self.recv(1, nolog=True)
		except:
			log.debug("Received {} bytes\n{}".format(green(len(data)), hexdump(data)))
		return data

	def sendline(self, data):
		self.send(data+b"\n")

	def sendafter(self, delim, data):
		received = self.recvuntil(delim)
		self.send(data)
		return received

	def sendlineafter(self, delim, data):
		received = self.recvuntil(delim)
		self.send(data+b"\n")
		return received
