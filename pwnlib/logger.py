import sys
from pwnlib.utils.colors import green, red, yellow
from pwnlib.utils.term   import term

class logger(object):
	"""Logger objects are used to log messages to files"""
	def __init__(self, level=1, stdout=sys.stdout, stderr=sys.stderr):
		super(logger, self).__init__()
		self.level = level
		self.stdout = stdout
		self.stderr = stderr

	def error(self, msg, details=None):
		if self.level >= 0:
			if details is not None:
				msg += "\n{}\n{}\n{}".format("\u2014"*term.columns, details, "─"*term.columns)
			self.stderr.write("[{}]: {}\n".format(red("ERROR"), msg))
	def info(self, msg, details=None):
		if self.level >= 1:
			if details is not None:
				msg += "\n{}\n{}\n{}".format("\u2014"*term.columns, details, "─"*term.columns)
			self.stdout.write("[{}]:  {}\n".format(green("INFO"), msg))

	def debug(self, msg, details=None):
		if self.level >= 2:
			if details is not None:
				msg += "\n{}\n{}\n{}".format("\u2014"*term.columns, details, "─"*term.columns)
			self.stderr.write("[{}]: {}\n".format(yellow("DEBUG"), msg))

log = logger()
