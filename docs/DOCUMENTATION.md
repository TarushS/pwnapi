
# Usage
Import the module with:
```python
from pwnapi import *
```

These are the objects and functions exposed by pwnapi:
```python
from pwnlib.context       import context
from pwnlib.logger        import log
from pwnlib.packer        import p8, u8, p16, u16, p32, u32, p64, u64
from pwnlib.binary        import ELF
from pwnlib.corefile      import core
from pwnlib.tubes.process import process
from pwnlib.tubes.remote  import remote
from pwnlib.utils.misc    import cyclic, cyclic_find, fit, shellcode
```

# log
The log object is used to set the logging level and to log messages to files.

There are 3 logging levels:

|Level | Value|
|-|-|
|ERROR|0|
|INFO|1|
|DEBUG|2

You can set the log level with:
```python
log.level = 2 # set to DEBUG level
```
Setting the log level to a value `n` means that only messages with level `>=n` will be logged.

By default `ERROR` and `DEBUG` messages are logged into `sys.stderr`, while `INFO` messages are logged to `sys.stdout`.

You can redirect output by overriding the properties `log.stdout` and `log.stderr` with other files opened in write mode.

You can log messages with:
```python
log.error("a message", "optional details")          # logged if log.level >=0
log.info("another message")                         # logged if log.level >=1
log.debug("another message", "optional details")    # logged if log.level >=2
```

# context
The context object contains informations about our CTF environment. At first it is empty.

You can use the `update` method to set its properties or you can do that directly:
```python
context.update(binary=ELF("challenge.bin"), host="ctf.target.com", port=4444)
context.port = 1337 # directly update a single property
```

The first parameter specifies the binary we are exploiting.

The ELF class is documented in a following paragraph.

You can then use the `getprocess` and `getremote` methods to spawn new instances of your process or connections to the target host and then interact with them.
```python
localTest = True
t = context.getprocess() if localTest else context.getremote()
#... interact
```

The `process` and `remote` classes are documented in following paragraphs.

# ELF
The `ELF` class lets you open a binary and retrieve information about it.

To create a new object you have to specify a path:
```python
e = ELF("challenge.bin")
```

This path can be later accessed with `e.path`.

Other general information are accessible through `info` property:
```python
e.info.arch
e.info.bits
e.info.endian
e.info.os
e.info.canary
e.info.nx
e.info.pic
e.info.relocs
e.info.sanitiz
e.info.stripped
```

It is possible to retrieve addresses from the GOT and PLT through the `sym` property.
```python
system_PLT = e.sym.plt.system # you can also use e.sym.plt["system"] notation
system_GOT = e.sym.got.system
```

# core
The `core` class lets you open a corefile and retrieve information from it.

To create a new object you have to specify a path:
```python
c = core("corefile")
```

You can read register values through the `regs` property.
```python
rax = c.regs["rax"]
```

You can read values from the stack through the `stack` property.
```python
top_of_stack = c.stack[0]
```

# Packing

You can simplify the conversion between bytes and integers with a set of functions.

For each integer type (`8` bits, `16` bits, `32` bits, `64` bits) you have the relative packing and unpacking function.

They accept two optional parameters to specify endianness and whether the number is signed.

By default numbers are supposed to be unsigned.

By default pwnapi tries to set endianness to the one specified in the `context.binary`, if no binary was specified it will be assumed to be `"little"`.
```python

p64(0x4142434445464748, endian="little", signed=False)
u32(b"\xff\xff\xff\xff", signed=True) # returns -1
#...etc
```

# Payload Generation
A set of functions is available to craft payloads.

The `fit({offset: data, ...})` function tries to put the specified data at specified offsets by putting padding where needed.

The `cyclic(n, alphabet)` function generates a payload of length `n` using the characters specified in the `alphabet` (if not specified lowercase letters are used) which will contain unique 4-bytes patterns.

In this way you can retrieve the offset of a specified 4-bytes pattern with `cyclic_find("caaa")`

# CLI utilities

## checksec
Check which mitigations are in place
```
$ checksec target_binary
[INFO]:  Opening binary target_binary
──────────────────────────────────────────────────────────────────────────────
arch                            x86
bits                            64
endian                          little
os                              linux
static                          False
stripped                        False
canary                          False
nx                              True
pic                             False
relocs                          True
sanitiz                         False
──────────────────────────────────────────────────────────────────────────────
```

## coreinfo
Extract informations from corefile
```
$ coreinfo corefile
[INFO]:  Registers
──────────────────────────────────────────────────────────────────────────────
rax     : 0xc8
rbx     : 0x0
rcx     : 0x7f933674d155
rdx     : 0x100
rsi     : 0x7fff0aa10410
rdi     : 0x0
r8      : 0x7fff0aa103c0
r9      : 0x0
r10     : 0x5640af9c0441
r11     : 0x246
r12     : 0x5640af9c0770
r13     : 0x7fff0aa10580
r14     : 0x0
r15     : 0x0
rip     : 0x5640af9c09b3
rbp     : 0x6261616562616164
rflags  : 0x10202
rsp     : 0x7fff0aa10488
──────────────────────────────────────────────────────────────────────────────
[INFO]:  Stack
──────────────────────────────────────────────────────────────────────────────
0x62616166
0x62616167
0x62616168
0x62616169
0x6261616a
0x6261616b
0x6261616c
0x6261616d
──────────────────────────────────────────────────────────────────────────────
```

## cyclic
Generate a cyclic pattern of length n
```
$ cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
```

## cyclic_find
Search 4 bytes in cyclic pattern
```
$ cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
```

## shellcode
generate shellcode
```
$ shellcode amd64 linux sh
jhH?/bin///sPH??hri?4$1?V^H?VH??1?j;X
```