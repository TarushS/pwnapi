import subprocess
from pwnlib.logger       import log
from pwnlib.tubes.tube   import tube
from pwnlib.utils.colors import green
from pwnlib.utils.misc   import hexdump

class process(tube):
	"""class to communicate with processes"""
	def __init__(self, args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
		super(process, self).__init__()		
		self.p = subprocess.Popen(args, stdin=stdin, stdout=stdout, stderr=stderr, shell=False)
		log.info("Process started with PID {} {}".format(green(self.p.pid), args))

	def close(self):
		self.p.stdin.close()
		self.p.stdout.close()
		self.p.stderr.close()
		self.p.terminate()
		self.p.wait()
		log.info("Process {} exited with code {}".format(green(self.p.pid), green(self.p.returncode)))

	def recv(self, size, nolog=False):
		data = self.p.stdout.read(size)
		if not nolog:
			log.debug("Received {} bytes\n{}".format(green(len(data)), hexdump(data)))
		return data

	def send(self, data):
		self.p.stdin.write(data)	
		log.debug("Sent {} bytes\n{}".format(green(len(data)), hexdump(data)))
		self.p.stdin.flush()

	def recvall(self):
		data = self.p.stdout.read()
		log.debug("Received {} bytes\n{}".format(green(len(data)), hexdump(data)))
		return data

	def recvline(self):
		data = self.p.stdout.readline()
		log.debug("Received {} bytes\n{}".format(green(len(data)), hexdump(data)))
		return data
