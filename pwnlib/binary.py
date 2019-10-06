import r2pipe, subprocess
from dotmap              import DotMap
from pwnlib.context      import context
from pwnlib.logger       import log
from pwnlib.tubes.tube   import tube
from pwnlib.utils.colors import green
from pwnlib.utils.term   import term

class ELF(object):
	"""class to extract data from binaries"""
	info = ["arch", "bits", "endian", "os", "static", "stripped", "canary",  "nx", "pic", "relocs", "sanitiz"]

	def __init__(self, path):
		super(ELF, self).__init__()
		self.path = path
		self.r2 = r2pipe.open(path)
		self.info = DotMap({i:self.r2.cmdj("ij")["bin"][i] for i in ELF.info})

		l = []
		for m in ELF.info:
			l.append(m)
			l.append(self.info[m])	
		log.info("Opening binary {}".format(self.path), ("{:32}{}\n"*len(ELF.info)).format(*l).strip())

		self.sym = DotMap()
		
		for i in self.r2.cmdj("isj"):
			self.sym[i["name"]] = i["vaddr"]

		self.sections = {i["name"]:i["vaddr"] for i in self.r2.cmdj("iSj")}
		
		self.sym.got = DotMap({i["name"]:i["vaddr"] for i in self.r2.cmdj("irj")})
		self.sym.plt = DotMap({i["name"]:i["plt"]   for i in self.r2.cmdj("iij")})

		log.debug("GOT {} entries".format(len(self.sym.got)), "\n".join(["{:32}0x{:016x}".format(r[0], r[1]) for r in self.sym.got.items()]))
		log.debug("PLT {} entries".format(len(self.sym.plt)), "\n".join(["{:32}0x{:016x}".format(r[0], r[1]) for r in self.sym.plt.items()]))

	def search(self, pattern):
		return iter([i["offset"] for i in self.r2.cmdj("/j {}".format(pattern))])