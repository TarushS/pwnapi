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
		self._base = 0

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

	@property
	def base(self):
		return self._base

	@base.setter
	def base(self, value):
		self._base = value
		self.info = DotMap({i:self.r2.cmdj("ij")["bin"][i] for i in ELF.info})
		self.r2.cmd("o {} {}".format(self.path, self._base))

		l = []
		for m in ELF.info:
			l.append(m)
			l.append(self.info[m])	

		self.sym = DotMap()
		
		for i in self.r2.cmdj("isj"):
			self.sym[i["name"]] = i["vaddr"]

		self.sections = {i["name"]:i["vaddr"] for i in self.r2.cmdj("iSj")}
		
		self.sym.got = DotMap({i["name"]:i["vaddr"] for i in self.r2.cmdj("irj")})
		self.sym.plt = DotMap({i["name"]:i["plt"]   for i in self.r2.cmdj("iij")})

	def search(self, pattern):
		return iter([i["offset"] for i in self.r2.cmdj("/j {}".format(pattern))])

	def ret2csu_gadgets(self):
		ins = list(reversed(self.r2.cmdj("af@sym.__libc_csu_init; pdfj@sym.__libc_csu_init;")["ops"]))
		assert(ins[0]["type"] == "ret")
		tmp = [ins[0]]
		for i in range(1, len(ins)):
			if ins[i]["type"] != "pop":
				break
			tmp.insert(0, ins[i])
		log.debug("ret2csu pops gadget", "\n".join(map(lambda x: "0x{:08x}: {}".format(x["offset"], x["disasm"]), tmp)))
		while ins[i]["type"] != "ucall":
			i += 1
		tmp2 = [ins[i]]
		while i < len(ins):
			i += 1
			if ins[i]["type"] != "mov":
				break
			tmp2.insert(0, ins[i])		
		log.debug("ret2csu mov&call gadget", "\n".join(map(lambda x: "0x{:08x}: {}".format(x["offset"], x["disasm"]), tmp2)))
		return tmp[0]["offset"], tmp2[0]["offset"]

	def findgadgetbystr(self, s):
		ins = s.split(";")[0]
		opcodes = self.r2.cmdj("\"/Rj {}\"".format(s))[0]["opcodes"]
		i = 0
		while opcodes[i]["opcode"] != ins:
			i += 1
		return opcodes[i]["offset"]
		
