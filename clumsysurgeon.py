
import os
import argparse
import r2pipe

'''
	The following functions are the dependency handlers for each instruction
	To add a new dependency handler create a function whose name is the instruction in question
	Then add an entry to the dependencyHandlers variable in the isDependent() function
	instr   - Instruction object for the instruction being analyzed
	var     - The variable being analyzed
	context - The context that has been and is being built up by the dependency handlers
	These functions must be defined prior to the declaration of the dependencyHandlers variable!!
'''
def inc(instr, var, context):
    naddr = instr["addr"]
    addr = str(hex(naddr))
    operands = instr["opex"]["operands"]
    if operands[0]["type"] != "mem":
		if "value" in operands[0] and operands[0]["value"] == var:
			print("Variable being incremented: " + addr + " " + instr["opcode"])
			context["varState"] = "(" + context["varState"] + ") + 1"
			context["dirty"] = True
                    
    elif parseMemory(naddr, operands[0]) == var:
		print("Variable being incremented: " + addr + " " + instr["opcode"])
		context["varState"] = "(" + context["varState"] + ") + 1"
		context["dirty"] = True

def dec(instr, var, context):
    naddr = instr["addr"]
    addr = str(hex(naddr))
    operands = instr["opex"]["operands"]
    if operands[0]["type"] != "mem":
		if "value" in operands[0] and operands[0]["value"] == var:
			print("Variable being decremented: " + addr + " " + instr["opcode"])
			context["varState"] = "(" + context["varState"] + ") - 1"
			context["dirty"] = True

    elif parseMemory(naddr, operands[0]) == var:
		print("Variable being decremented: " + addr + " " + instr["opcode"])
		context["varState"] = "(" + context["varState"] + ") - 1"
		context["dirty"] = True


def mov(instr, var, context):
	naddr = instr["addr"]
	addr = str(hex(naddr))
	operands = instr["opex"]["operands"]
	if operands[0]["type"] != "mem":	
		if "value" in operands[0] and operands[0]["value"] == var:
			print("Variable being overwritten: " + addr + " " + instr["opcode"])
			if "value" in operands[1]:
				context["varState"] = operands[1]["value"] + "@" + addr
				context["dirty"] = True
			else:
				context["varState"] = parseMemory(naddr, operands[1]) + "@" + addr
				context["dirty"] = True

	elif parseMemory(naddr, operands[0]) == var:
		print("Variable being overwritten: " + addr + " " + instr["opcode"])
		if "value" in operands[1]:                                        
			context["varState"] = operands[1]["value"] + "@" + addr
			context["dirty"] = True
		else:
			context["varState"] = parseMemory(naddr, operands[1]) + "@" + addr
			context["dirty"] = True

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
				context["dirty"] = True
			else:
				print("Variable being bitmasked: " + addr + " " + opcd)
				if "value" in operands[1]:
					print operands[1]['value']
					# operands[1]['value'] may not always be a string
					context["varState"] = "(" + context["varState"] + ") | " + operands[1]["value"]
					context["dirty"] = True
				else:
					context["varState"] = "(" + context["varState"] + ") | " + parseMemory(naddr, operands[1])  
					context["dirty"] = True
	elif parseMemory(naddr, operands[0]) == var:
		print("Variable being bitmasked: " + addr + " " + opcd)
		if "value" in operands[1]:
			context["varState"] = "(" + context["varState"] + ") | " + operands[1]["value"]
			context["dirty"] = True
		else:
			context["varState"] = "(" + context["varState"] + ") | " + parseMemory(naddr, operands[1])
			context["dirty"] = True

	# There is an elif here to make sure that if there is a xor eax, eax type
	# instruction we won't trigger two outputs (zeroing out is printed in the above block)
	elif operands[1]["type"] != "mem":
		if "value" in operands[1] and operands[1]["value"] == var:
			print("Variable being used as a bitmask: " + addr + " " + opcd)
	elif parseMemory(naddr, operands[1]) == var:
		print("Variable being used as a bitmask: " + addr + " " + opcd)


''' 
	This function parses a memory operand and prints it in nice form
	It will do nice things like evaluate rip (note: currently doesn't work for eip, fix that)
	addr - The address of the instruction which uses the given piece of memory as an operand. Address is input as a decimal integer.
	oper - The operand object for the given piece of memory
''' 
def parseMemory(addr, oper):
	scale = oper["scale"]
	disp  = oper["disp"]
	size  = oper["size"]
	sizeTable = {1 : "byte", 2 : "word", 4 : "dword", 8 : "qword"}

	if "base" in oper:
		base = oper["base"]
		# If base isn't RIP then just use that register as the first term
		if base != "rip":			
			front = base			
		# If the base is RIP then simplify output by adding instr. address to displacement
		else:					
		   	front = str(hex(addr + disp))

		if "index" in oper:
			index = oper["index"]
			# Simplify multiplication away if scale = 1
			if scale == 1:			
				mult = ""
			else:
				mult = str(scale) + "*"

			# If there isn't an end term because disp = 0 or the base is RIP, exclude the final + sign
			if disp == 0 or base == "rip":	
				middle = " + " + mult + index
			else:
				middle = " + " + mult + index + " + "
		else:
			# If there's no index there's no middle term
			if disp == 0 or base == "rip":	
				middle = ""
			else:
				# Put a space here instead if there's an end term
				middle = " "		

		if base != "rip" and disp != 0:
			# Print the right sign for the displacement
			if disp > 0:			
				end = "+ " + str(hex(disp))
			else:
				end = "- " + str(hex(-disp))
		else:
			# No term if there's no displacement or if base is RIP
			end = ""			

		return sizeTable[size] + " [" + front + middle + end + "]"
		
	# This handles the other kind of mem object, a memory segment. This probably isn't generic enough to handle everything yet.
	elif "segment" in oper:				
		segment = oper["segment"]
		return sizeTable[size] + " " + segment + ":[" + str(hex(disp)) + "]"

'''
	This is the fall-back function if no dependency handler is specified
	It will not affect the context (since it won't know what to do exactly)
	This will still pick out instructions which have the variable as an operand though	
'''
def generic(instr, var, context):
	naddr = instr["addr"]
	addr  = str(hex(instr["addr"]))
	for oper in instr["opex"]["operands"]:
		if "value" in oper and oper["value"] == var:
			print("Variable found in operand: " + addr + " " + instr["opcode"])
		elif oper["type"]=="mem" and parseMemory(addr, oper) == var:
			print("Variable found in operand: " + addr + " " + instr["opcode"])


'''
	This is our little dispatch function which picks out the instruction type and sends it off to the appropriate handler
	addr    - The address of the instruction which is being analyzed. Address is input as a decimal integer.
	var     - This is the variable being analyzed
	context - This is the context we are building up. It contains the information we're extracting about the variable.
'''
def isDependent(r2, addr, var, context):
	dependencyHandlers = {"mov" : mov, "xor": xor, "dec": dec, "inc": inc}
	naddr = addr
	addr  = str(hex(addr))

	r2.cmd("s " + addr)
	instr = r2.cmdj("aoj")[0]

	if instr["mnemonic"] in dependencyHandlers:
		dependencyHandlers[instr["mnemonic"]](instr, var, context)
	else:
		generic(instr, var, context)


'''
	var - The variable being examined. Examples: var = "ecx", var = "qword [rax]", var = "dword [0x28932]", var = "byte [rbp + 2*rsp + 0x37283]"
	context - This is our big bag of information. This will be populated by the dependency handlers with all the info that they gain.
	
	Currently there is only the variable state being tracked, but more entries will be added as needed.
	start  - This is the first function or address to start at. Addresses are written as hex strings.
	finish - This is the last address to analyze.
	bb     - The basic block that contains the start address, but not necessarily the finish address
	addr   - This is the address of the first instruction in the basic block, written in the form of a hex string, e.g. "0x4000ba"
'''
if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument("arg", nargs='*')
	args   = parser.parse_args()

	if not args.arg:
		print "USAGE: clumsysurgeon.py [infile]"
		exit(1)

	r2 = r2pipe.open(os.path.realpath(args.arg[0]))
	r2.cmd("aaaa")

	var    = "rsp"
	start  = "main"

	r2.cmd("s " + start)

	bb      = r2.cmdj("pdbj")
	addr    = str(hex(bb[0]["offset"]))
	context = {"varState" : var+"@"+addr, "dirty" : False}

	#finish  = str(hex(bb[len(bb) - 1]["offset"]))
	finish  = "0x402a2a" # different for everyone


	# make me a function. and put me in a loop
	for line in bb:
		# Check to see that we're in the bounds (block boundary or function boundary or both?)
		if line["offset"] > int(finish, 16):
			break

		# Keep track of the current variable state to check if it changes after isDependent()
		oldState  = context["varState"]
		dirtiness = context["dirty"]

		isDependent(r2, line["offset"], var, context)

		if oldState != context["varState"]:
			print("***Variable value: " + context["varState"])
		if dirtiness != context["dirty"]:
			print("***Variable dirtied: " + "True" if context["dirty"] else "False")

	r2.quit()
