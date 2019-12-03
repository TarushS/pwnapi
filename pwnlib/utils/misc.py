from pwnlib.logger import log
from pwnlib.utils.term import term
import string, struct
from dotmap              import DotMap

shellcode = DotMap({"amd64":{"linux":{"sh":b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'}}})

def hexdump(data):
	dump = ""
	clear = ""
	i = 0

	for b in data:
		dump += "{:02x} ".format(b)
		c = chr(b) if b>=32 and b<=127 else "."
		clear += c
		i += 1

		if i%4==0:
			dump += "  "
		if i%16==0:
			dump += "│ {}\n".format(clear)
			clear = ""
		
	if clear != "":
		dump += " "*(56-len(dump.split("\n")[-1]))
		dump += "│ "+clear
	return "\u2500"*56+"\u252c"+"\u2500"*(term.columns-56-1)+"\n"+dump+"\n"+"\u2500"*56+"\u2534"+"\u2500"*(term.columns-56-1)

def fit(data):
	data = sorted(data.items(), key=lambda x: x[0])
	
	for i in range(len(data)-1):
		if data[i][0] + len(data[i][1]) > data[i+1][0]:
			log.error("Overlapping ranges")
			exit(-1)

	payload = b""

	for i in data:
		payload = payload.ljust(i[0], b"A")
		payload += i[1]

	return payload

def de_brujin(n, k):
    """ source from wikipedia
    de Bruijn sequence for alphabet k
    and subsequences of length n.
    """
    alphabet = k
    k = len(k)

    a = [0] * k * n
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return "".join(alphabet[i] for i in sequence)

def cyclic(size, alphabet=string.ascii_letters[:26]):
	return bytes(de_brujin(4, alphabet)[:size], encoding="utf-8")

def cyclic_find(pattern, alphabet=string.ascii_letters[:26]):
	if type(pattern) == int:
		pattern = struct.pack("<i", pattern).decode("utf-8")
	return de_brujin(4, alphabet).find(pattern)
