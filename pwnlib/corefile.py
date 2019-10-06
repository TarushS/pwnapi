import r2pipe
from dotmap              import DotMap
from pwnlib.logger       import log

class core(object):
	"""class to extract data from corefiles"""
	def __init__(self, path):
		super(core, self).__init__()
		self.path = path
		self.r2 = r2pipe.open(path, ["-2"])
		self.regs = DotMap(self.r2.cmdj("drj"))
		self.stack = self.r2.cmdj("pxwj @rsp")