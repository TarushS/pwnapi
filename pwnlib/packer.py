import struct
from pwnlib.context import context

class packer(object):
	"""Utilities to pack/unpack data"""
	_fmtTable = { "little":	{	True:	{8:"<b", 16:"<h", 32:"<i", 64:"<q"},
								False:	{8:"<B", 16:"<H", 32:"<I", 64:"<Q"}
				},
				   "big":	{	True:	{8:">b", 16:">h", 32:">i", 64:">q"},
								False:	{8:">B", 16:">H", 32:">I", 64:">Q"}
				}
		}

	@classmethod
	def _p(self, n, endian, signed, size):
		if endian is None:
			endian = context.binary.info.endian if context.binary is not None else "little"
		return struct.pack(self._fmtTable[endian][signed][size], n)

	@classmethod
	def _u(self, n, endian, signed, size):
		if endian is None:
			endian = context.binary.info.endian if context.binary is not None else "little"
		return struct.unpack(self._fmtTable[endian][signed][size], n)[0]

	@classmethod
	def p8(self, n, endian=None, signed=False):
		return self._p(n, endian=endian, signed=signed, size=8)

	@classmethod
	def u8(self, n, endian=None, signed=False):
		return self._u(n, endian=endian, signed=signed, size=8)

	@classmethod
	def p16(self, n, endian=None, signed=False):
		return self._p(n, endian=endian, signed=signed, size=16)

	@classmethod
	def u16(self, n, endian=None, signed=False):
		return self._u(n, endian=endian, signed=signed, size=16)

	@classmethod
	def p32(self, n, endian=None, signed=False):
		return self._p(n, endian=endian, signed=signed, size=32)

	@classmethod
	def u32(self, n, endian=None, signed=False):
		return self._u(n, endian=endian, signed=signed, size=32)

	@classmethod
	def p64(self, n, endian=None, signed=False):
		return self._p(n, endian=endian, signed=signed, size=64)

	@classmethod
	def u64(self, n, endian=None, signed=False):
		return self._u(n, endian=endian, signed=signed, size=64)

p8  = packer.p8
u8  = packer.u8
p16 = packer.p16
u16 = packer.u16
p32 = packer.p32
u32 = packer.u32
p64 = packer.p64
u64 = packer.u64
