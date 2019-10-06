import socket
from pwnlib.logger       import log
from pwnlib.tubes.tube   import tube
from pwnlib.utils.misc   import hexdump
from pwnlib.utils.colors import green, red

class remote(tube):
	"""class to communicate with remote sockets"""
	def __init__(self, host, port, timeout=5):
		super(remote, self).__init__()		
		self.s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.settimeout(timeout)
		self.s.connect((host, port))
		self.host = host
		self.port = port
		log.info("Connecting to {} on port {}".format(green(host), green(port)))

	def close(self):
		self.s.shutdown(socket.SHUT_RDWR)
		self.s.close()
		log.info("Closed connection with {} on port {}".format(green(self.host), green(self.port)))

	def recv(self, size, nolog=False):
		data = self.s.recv(size)
		if not nolog:
			log.debug("Received {} bytes\n{}".format(green(len(data)), hexdump(data)))
		return data

	def send(self, data):
		self.s.sendall(data)
		log.debug("Sent {} bytes\n{}".format(green(len(data)), hexdump(data)))
