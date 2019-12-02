from setuptools import setup

setup(name="pwnapi",
      version="2019.10.6",
      author="nico",
      license="https://github.com/ndaprela/pwnapi/blob/master/LICENSE",
      url="https://github.com/ndaprela/pwnapi",
      description="",
      long_description="https://github.com/ndaprela/pwnapi/README.md",
      packages=["pwnapi", "pwnlib"],
      scripts=["bin/checksec", "bin/coreinfo", "bin/cyclic", "bin/cyclic_find", "bin/p64", "bin/shellcode"]
    )
