import r2pipe
r2 = r2pipe.open("/home/ian/projectcapstone/tests/asmsrc/antivm-cpu-polymorph-test")

def inc(instr, var, context):
        naddr = instr["addr"]
        addr = str(hex(naddr))
        operands = instr["opex"]["operands"]
        if operands[0]["type"] != "mem":
                if "value" in operands[0] and operands[0]["value"] == var:
                        print("Variable being incremented: " + addr + " " + instr["opcode"])
                        context["varState"] = "(" + context["varState"] + ") + 1"
                        
        elif parseMemory(naddr, operands[0]) == var:
                print("Variable being incremented: " + addr + " " + instr["opcode"])
                context["varState"] = "(" + context["varState"] + ") + 1"

def dec(instr, var, context):
        naddr = instr["addr"]
        addr = str(hex(naddr))
        operands = instr["opex"]["operands"]
        if operands[0]["type"] != "mem":
                if "value" in operands[0] and operands[0]["value"] == var:
                        print("Variable being decremented: " + addr + " " + instr["opcode"])
                        context["varState"] = "(" + context["varState"] + ") - 1"

        elif parseMemory(naddr, operands[0]) == var:
                print("Variable being decremented: " + addr + " " + instr["opcode"])
                context["varState"] = "(" + context["varState"] + ") - 1"


def mov(instr, var, context):
	naddr = instr["addr"]
	addr = str(hex(naddr))
	operands = instr["opex"]["operands"]
	if operands[0]["type"] != "mem":	
		if "value" in operands[0] and operands[0]["value"] == var:
			print("Variable being overwritten: " + addr + " " + instr["opcode"])
                        if "value" in operands[1]:
 	                       context["varState"] = operands[1]["value"] + "@" + addr
                        else:
                               context["varState"] = parseMemory(naddr, operands[1]) + "@" + addr

	elif parseMemory(naddr, operands[0]) == var:
		print("Variable being overwritten: " + addr + " " + instr["opcode"])
                if "value" in operands[1]:                                        
                        context["varState"] = operands[1]["value"] + "@" + addr
                else:
                        context["varState"] = parseMemory(naddr, operands[1]) + "@" + addr

			
	if operands[1]["type"] != "mem":
		if "value" in operands[1] and operands[1]["value"] == var:
			print("Variable being copied: " + addr + " " + instr["opcode"])
	elif parseMemory(naddr, operands[1]) == var:
		print("Variable being copied: " + addr + " " + instr["opcode"])		

def xor(instr, var, context):
	naddr = instr["addr"]
	addr = str(hex(naddr))
	opcd = instr["opcode"]
	operands = instr["opex"]["operands"]
        if operands[0]["type"] != "mem":
                if "value" in operands[0] and operands[0]["value"] == var:
			if "value" in operands[1] and operands[1]["value"] == var:
				print("Variable being zeroed out (" + var + " = 0): " + addr + " " + opcd)
				context["varState"] = "0"
			else:
                        	print("Variable being bitmasked: " + addr + " " + opcd)
				if "value" in operands[1]:
					context["varState"] = "(" + context["varState"] + ") | " + operands[1]["value"]
				else:
					context["varState"] = "(" + context["varState"] + ") | " + parseMemory(naddr, operands[1])  
        elif parseMemory(naddr, operands[0]) == var:
                print("Variable being bitmasked: " + addr + " " + opcd)
                if "value" in operands[1]:
                	context["varState"] = "(" + context["varState"] + ") | " + operands[1]["value"]
                else:
                	context["varState"] = "(" + context["varState"] + ") | " + parseMemory(naddr, operands[1])

	# There is an elif here to make sure that if there is a xor eax, eax type
	# instruction we won't trigger two outputs (zeroing out is printed in the above block)
        elif operands[1]["type"] != "mem":
                if "value" in operands[1] and operands[1]["value"] == var:
                        print("Variable being used as a bitmask: " + addr + " " + opcd)
        elif parseMemory(naddr, operands[1]) == var:
                print("Variable being used as a bitmask: " + addr + " " + opcd)

	
def generic(instr, var, context):
	naddr = instr["addr"]
	addr = str(hex(instr["addr"]))
	for oper in instr["opex"]["operands"]:
        	if "value" in oper and oper["value"] == var:
                	print("Variable found in operand: " + addr + " " + instr["opcode"])
                elif oper["type"]=="mem": #and parseMemory(addr, oper) == var:
                        print("Memory found: " + addr + " " + instr["opcode"])
                        print("After parsing: " + parseMemory(naddr, oper))


dependencyHandlers = {"mov" : mov, "xor": xor, "dec": dec, "inc": inc}

def isDependent(addr, var, context):
	naddr = addr
	addr = str(hex(addr))
#	context = {"varState" : var+"@"+addr}
	r2.cmd("s " + addr)
	instr = r2.cmdj("aoj")[0]
	if instr["mnemonic"] in dependencyHandlers:
		dependencyHandlers[instr["mnemonic"]](instr, var, context)
	else:
		generic(instr, var, context)
#	for oper in instr["opex"]["operands"]:
#		if "value" in oper and oper["value"] == var:
#			print("Variable found in operand: " + addr + " " + instr["opcode"])
#		elif oper["type"]=="mem": #and parseMemory(addr, oper) == var:
#			print("Memory found: " + addr + " " + instr["opcode"])
#			print("After parsing: " + parseMemory(naddr, oper))

def parseMemory(addr, oper):
	scale = oper["scale"]
	disp = oper["disp"]
	size = oper["size"]
	sizeTable = {1 : "byte", 2 : "word", 4 : "dword", 8 : "qword"}
	if "base" in oper:
		base = oper["base"]
	#	if "index" in oper:		
		#	index = oper["index"]
		#	if base == "rip" or disp == 0:
		#		return sizeTable[size] + " [" + str(hex(addr + disp)) + " + " + str(scale) + "*" + index + "]"
		#	else:
		if base != "rip":
			front = base
		else:
		   	front = str(hex(addr + disp))

		if "index" in oper:
			index = oper["index"]
			if scale == 1:
				mult = ""
			else:
				mult = str(scale) + "*"

			if disp == 0 or base == "rip":
				middle = " + " + mult + index
			else:
				middle = " + " + mult + index + " + "
		else:
			if disp == 0 or base == "rip":
				middle = ""
			else:
				middle = " "

		if base != "rip" and disp != 0:
			if disp > 0:
				end = "+ " + str(hex(disp))
			else:
				end = "- " + str(hex(-disp))
		else:
			end = ""

		return sizeTable[size] + " [" + front + middle + end + "]"
	#	else:
        #                if base == "rip" or disp == 0:
        #                        return sizeTable[size] + " [" + str(hex(addr + disp)) + "]"
	#		else:
	#			return sizeTable[size] + " [" + base + " + " + str(hex(disp)) + "]"
	elif "segment" in oper:
		segment = oper["segment"]
		return sizeTable[size] + " " + segment + ":[" + str(hex(disp)) + "]"
		


r2.cmd("aaaa")
r2.cmd("s entry0")
bb = r2.cmdj("pdbJ")
var = "ecx"
addr = str(hex(bb[0]["offset"]))
context = {"varState" : var+"@"+addr}
start = "entry0"
finish = "0x4000be"

for line in r2.cmdj("pdbJ"):
	if line["offset"] > int(finish, 16):
		break
	oldState = context["varState"]
	isDependent(line["offset"], var, context)
	if oldState != context["varState"]:
		print("***Variable value: " + context["varState"])
