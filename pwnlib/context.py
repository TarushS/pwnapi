from pwnlib.tubes.process import process
from pwnlib.tubes.remote  import remote

class Context(object):
	"""docstring for Context"""
	def __init__(self, binary=None, host=None, port=None):
		super(Context, self).__init__()
		self.binary = binary
		self.host = host
		self.port = port

	def update(self, binary=None, host=None, port=None):
		if binary is not None:
			self.binary = binary
		if host is not None:
			self.host = host
		if port is not None:
			self.port = port

	def getprocess(self):
		return process(self.binary.path)

	def getremote(self):
		return remote(self.host, self.port)
		
context = Context()