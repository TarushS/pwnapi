import shutil

class terminal(object):
	"""Basic terminal class"""	
	@property
	def columns(self):
		return shutil.get_terminal_size(fallback=(80, 24))[0]

	@property
	def rows(self):
		return shutil.get_terminal_size(fallback=(80, 24))[1]

term = terminal()