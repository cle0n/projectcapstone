#!/usr/bin/python
import r2pipe

filename = "/home/liam/list.txt";
r2 = r2pipe.open("/home/liam/hello.out")

r2.cmd("aaaa")

with open(filename) as f:
	content = f.read().splitlines()
	for index in range(len(content)):	
		cmd = r2.cmd("/j " + content[index])
		addr = str(hex(cmd[0]["offset"]))
		print addr


