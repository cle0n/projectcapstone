# Import r2pipe and open a file
# r2 must be defined prior to the declaration of isDependent(), since isDependent() makes use of r2
import r2pipe
r2 = r2pipe.open("/bin/ls")

# The following functions are the dependency handlers for each instruction
# To add a new dependency handler create a function whose name is the instruction in question
# Then add an entry to the dependencyHandlers variable in the isDependent() function
# instr   - Instruction object for the instruction being analyzed
# var     - The variable being analyzed
# context - The context that has been and is being built up by the dependency handlers
# These functions must be defined prior to the declaration of the dependencyHandlers variable!!

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

# This is the fall-back function if no dependency handler is specified
# It will not affect the context (since it won't know what to do exactly)
# This will still pick out instructions which have the variable as an operand though	
def generic(instr, var, context):
	naddr = instr["addr"]
	addr = str(hex(instr["addr"]))
	for oper in instr["opex"]["operands"]:
        	if "value" in oper and oper["value"] == var:
                	print("Variable found in operand: " + addr + " " + instr["opcode"])
                elif oper["type"]=="mem" and parseMemory(addr, oper) == var:
                        print("Variable found in operand: " + addr + " " + instr["opcode"])


# This is our little dispatch function which picks out the instruction type and sends it off to the appropriate handler
# addr    - The address of the instruction which is being analyzed. Address is input as a decimal integer.
# var     - This is the variable being analyzed
# context - This is the context we are building up. It contains the information we're extracting about the variable.
def isDependent(addr, var, context):
	dependencyHandlers = {"mov" : mov, "xor": xor, "dec": dec, "inc": inc}
	naddr = addr
	addr = str(hex(addr))
	r2.cmd("s " + addr)
	instr = r2.cmdj("aoj")[0]
	if instr["mnemonic"] in dependencyHandlers:
		dependencyHandlers[instr["mnemonic"]](instr, var, context)
	else:
		generic(instr, var, context)

# This function parses a memory operand and prints it in nice form
# It will do nice things like evaluate rip (note: currently doesn't work for eip, fix that)
# addr - The address of the instruction which uses the given piece of memory as an operand. Address is input as a decimal integer.
# oper - The operand object for the given piece of memory
def parseMemory(addr, oper):
	scale = oper["scale"]
	disp = oper["disp"]
	size = oper["size"]
	sizeTable = {1 : "byte", 2 : "word", 4 : "dword", 8 : "qword"}
	if "base" in oper:
		base = oper["base"] 			# Base register
		if base != "rip":			# If base isn't RIP then just use that register as the first term
			front = base			
		else:					# If the base is RIP then simplify output by adding instr. address to displacement
		   	front = str(hex(addr + disp))

		if "index" in oper:
			index = oper["index"]
			if scale == 1:			# Simplify multiplication away if scale = 1
				mult = ""
			else:
				mult = str(scale) + "*"

			if disp == 0 or base == "rip":	# If there isn't an end term because disp = 0 or the base is RIP, exclude the final + sign
				middle = " + " + mult + index
			else:
				middle = " + " + mult + index + " + "
		else:
			if disp == 0 or base == "rip":	# If there's no index there's no middle term
				middle = ""
			else:
				middle = " "		# Put a space here instead if there's an end term

		if base != "rip" and disp != 0:
			if disp > 0:			# Print the right sign for the displacement
				end = "+ " + str(hex(disp))
			else:
				end = "- " + str(hex(-disp))
		else:
			end = ""			# No term if there's no displacement or if base is RIP

		return sizeTable[size] + " [" + front + middle + end + "]"

	elif "segment" in oper:				# This handles the other kind of memory object, a memory segment. This probably isn't generic enough to handle everything yet.
		segment = oper["segment"]
		return sizeTable[size] + " " + segment + ":[" + str(hex(disp)) + "]"
		



# var - The variable being examined. Examples: var = "ecx", var = "qword [rax]", var = "dword [0x28932]", var = "byte [rbp + 2*rsp + 0x37283]"
# context - This is our big bag of information. This will be populated by the dependency handlers with all the info that they gain.
#  	   Currently there is only the variable state being tracked, but more entries will be added as needed.
# start - This is the first function or address to start at. Addresses are written as hex strings.
# finish - This is the last address to analyze.
# bb - The basic block that contains the start address, but not necessarily the finish address
# addr - This is the address of the first instruction in the basic block, written in the form of a hex string, e.g. "0x4000ba"


var = "rax"

start = "main"
finish = "0x4048b4"


r2.cmd("aaaa")
r2.cmd("s " + start)
bb = r2.cmdj("pdbj")
addr = str(hex(bb[0]["offset"]))
context = {"varState" : var+"@"+addr, "dirty" : False}

for line in bb:
	# Check to see that we're in the bounds 
	# start <= offset <= finish
	if line["offset"] > int(finish, 16):
		break
	# Keep track of the current variable state to check if it changes after isDependent()
	oldState = context["varState"]
	dirtiness = context["dirty"]
	# Run our dependency analyzer
	isDependent(line["offset"], var, context)

	# Print the new variable state if the state changed
	if oldState != context["varState"]:
		print("***Variable value: " + context["varState"])
	if dirtiness != context["dirty"]:
		print("***Variable dirtied: " + "True" if context["dirty"] else "False")
