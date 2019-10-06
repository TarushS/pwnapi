class colors(object):
	"""Color support, for the moment minimal 8 colors support"""
	codes = {"black":   "\u001b[30m",
			 "red":     "\u001b[31m",
			 "green":   "\u001b[32m",
			 "yellow":  "\u001b[33m",
			 "blue":    "\u001b[34m",
			 "magenta": "\u001b[35m",
			 "cyan":    "\u001b[36m",
			 "white":   "\u001b[37m",
			 "reset":   "\u001b[0m"
	        }
	
	@classmethod
	def _colorize(self, msg, color):
		return "{}{}{}".format(self.codes[color], msg, self.codes["reset"])

	@classmethod
	def black(self, msg):
		return self._colorize(msg, color="black")
		
	@classmethod
	def red(self, msg):
		return self._colorize(msg, color="red")
		
	@classmethod
	def green(self, msg):
		return self._colorize(msg, color="green")
		
	@classmethod
	def yellow(self, msg):
		return self._colorize(msg, color="yellow")
		
	@classmethod
	def blue(self, msg):
		return self._colorize(msg, color="blue")
		
	@classmethod
	def magenta(self, msg):
		return self._colorize(msg, color="magenta")
		
	@classmethod
	def cyan(self, msg):
		return self._colorize(msg, color="cyan")
		
	@classmethod
	def white(self, msg):
		return self._colorize(msg, color="white")
		
	@classmethod
	def reset(self, msg):
		return self._colorize(msg, color="reset")

black   = colors.black
red     = colors.red
green   = colors.green
yellow  = colors.yellow
blue    = colors.blue
magenta = colors.magenta
cyan    = colors.cyan
white   = colors.white
reset   = colors.reset