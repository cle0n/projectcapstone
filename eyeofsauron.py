'''
	Eye Of Sauron

	class Nazgul     : Dependency Handlers
	class EyeOfSauron: Context Manager

	notes:
	- 

'''

class Nazgul:

	def __init__(self):
		self.DEPENDENCYHANDLERS = {
			'mov': self._mov,
			'xor': self._xor,
			'inc': self._inc,
			'dec': self._dec,
			'gen': self._gen,
		}

	'''
		The following methods (prefixed with '_') are the dependency handlers for 
		each instruction. To add a new dependency handler create a function whose 
		name is the instruction in question and add it to the DEPENDENCYHANDLERS.

		instr   - Instruction object for the instruction being analyzed
		var     - The variable being analyzed
		context - The context that has been and is being built up by the dependency
		          handlers
	'''
###################################################################################
	def _inc(self, instr, var, context):
		naddr = instr["addr"]
		addr = str(hex(naddr))
		operands = instr["opex"]["operands"]
		if operands[0]["type"] != "mem":
			if "value" in operands[0] and operands[0]["value"] == var:
				print("Variable being incremented: " + addr + " " + instr["opcode"])
				context["varState"] = "(" + context["varState"] + ") + 1"
				context["dirty"] = True
		                
		elif self.parseMemory(naddr, operands[0]) == var:
			print("Variable being incremented: " + addr + " " + instr["opcode"])
			context["varState"] = "(" + context["varState"] + ") + 1"
			context["dirty"] = True

	def _dec(self, instr, var, context):
		naddr = instr["addr"]
		addr = str(hex(naddr))
		operands = instr["opex"]["operands"]
		if operands[0]["type"] != "mem":
			if "value" in operands[0] and operands[0]["value"] == var:
				print("Variable being decremented: " + addr + " " + instr["opcode"])
				context["varState"] = "(" + context["varState"] + ") - 1"
				context["dirty"] = True

		elif self.parseMemory(naddr, operands[0]) == var:
			print("Variable being decremented: " + addr + " " + instr["opcode"])
			context["varState"] = "(" + context["varState"] + ") - 1"
			context["dirty"] = True


	def _mov(self, instr, var, context):
		naddr = instr["addr"]
		addr = str(hex(naddr))
		operands = instr["opex"]["operands"]
		if operands[0]["type"] != "mem":	
			if "value" in operands[0] and operands[0]["value"] == var:
				print("Variable being overwritten: " + addr + " " + instr["opcode"])
				if "value" in operands[1]:
					if operands[1]["type"] == "imm":
						context["varState"] = str(operands[1]["value"])
					else:
						context["varState"] = operands[1]["value"] + "@" + addr
					context["dirty"] = True
				else:
					context["varState"] = self.parseMemory(naddr, operands[1]) + "@" + addr
					context["dirty"] = True

		elif self.parseMemory(naddr, operands[0]) == var:
			print("Variable being overwritten: " + addr + " " + instr["opcode"])
			if "value" in operands[1]:                                        
				if operands[1]["type"] == "imm":
					context["varState"] = str(operands[1]["value"])
				else:
					context["varState"] = operands[1]["value"] + "@" + addr
				context["dirty"] = True
			else:
				context["varState"] = self.parseMemory(naddr, operands[1]) + "@" + addr
				context["dirty"] = True

		if operands[1]["type"] != "mem":
			if "value" in operands[1] and operands[1]["value"] == var:
				print("Variable being copied: " + addr + " " + instr["opcode"])

		elif self.parseMemory(naddr, operands[1]) == var:
			print("Variable being copied: " + addr + " " + instr["opcode"])		

	def _xor(self, instr, var, context):
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
						context["varState"] = "(" + context["varState"] + ") | " + self.parseMemory(naddr, operands[1])  
						context["dirty"] = True
		elif self.parseMemory(naddr, operands[0]) == var:
			print("Variable being bitmasked: " + addr + " " + opcd)
			if "value" in operands[1]:
				context["varState"] = "(" + context["varState"] + ") | " + operands[1]["value"]
				context["dirty"] = True
			else:
				context["varState"] = "(" + context["varState"] + ") | " + self.parseMemory(naddr, operands[1])
				context["dirty"] = True

		# There is an elif here to make sure that if there is a xor eax, eax type
		# instruction we won't trigger two outputs (zeroing out is printed in the 
		# above block)
		elif operands[1]["type"] != "mem":
			if "value" in operands[1] and operands[1]["value"] == var:
				print("Variable being used as a bitmask: " + addr + " " + opcd)
		elif self.parseMemory(naddr, operands[1]) == var:
			print("Variable being used as a bitmask: " + addr + " " + opcd)


	'''
		This is the fall-back function if the requested dependency handler isn't
		found. It will not affect the context (since it won't know what to do 
		exactly). This will still pick out instructions which have the variable as 
		an operand though.	
	'''
	def _gen(self, instr, var, context):
		naddr = instr["addr"]
		addr  = str(hex(instr["addr"]))
		for oper in instr["opex"]["operands"]:
			if "value" in oper and oper["value"] == var:
				print("Variable found in operand: " + addr + " " + instr["opcode"])
			elif oper["type"]=="mem" and self.parseMemory(addr, oper) == var:
				print("Variable found in operand: " + addr + " " + instr["opcode"])

	''' 
		This function parses a memory operand and prints it in nice form
		It will do nice things like evaluate rip (for 64-bit code only)
		addr - The address of the instruction which uses the given piece of memory
		       as an operand. Address is input as a decimal integer.
		oper - The operand object for the given piece of memory
	''' 
###################################################################################
	def parseMemory(self, addr, oper):
		scale = oper["scale"]
		disp  = oper["disp"]
		size  = oper["size"]
		sizeTable = {1 : "byte", 2 : "word", 4 : "dword", 8 : "qword"}

		if "base" in oper:
			base = oper["base"]
			# If base isn't RIP then just use that register as the first term
			if base != "rip":			
				front = base			
			# If the base is RIP then simplify output by adding instr. address to 
			# displacement
			else:					
			   	front = str(hex(addr + disp))

			if "index" in oper:
				index = oper["index"]
				# Simplify multiplication away if scale = 1
				if scale == 1:			
					mult = ""
				else:
					mult = str(scale) + "*"

				# If there isn't an end term because disp = 0 or the base is RIP,
				# exclude the final + sign
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
			
		# This handles the other kind of mem object, a memory segment. This 
		# probably isn't generic enough to handle everything yet.
		elif "segment" in oper:				
			segment = oper["segment"]
			return sizeTable[size] + " " + segment + ":[" + str(hex(disp)) + "]"


	def CallHandler(self, var, instr, ctx):
		if instr['mnemonic'] in self.DEPENDENCYHANDLERS:
			self.DEPENDENCYHANDLERS[instr['mnemonic']](instr, var, ctx)
		else:
			self.DEPENDENCYHANDLERS['gen'](instr, var, ctx)

'''
    var - The variable being examined. Examples: var = "ecx", var = "qword [rax]", 
          var = "dword [0x28932]", var = "byte [rbp + 2*rsp + 0x37283]", etc.

    ctx - This is our big bag of information. This will be populated by the 
          dependency handlers with all the info that they gain.
	
	Currently there is only the variable state being tracked, but more entries will
    be added as needed.

'''
class EyeOfSauron:

	def __init__(self):
		self.cdict   = { }
		self.handler = Nazgul()

	# Creates and appends a new dictionary to our dictionary of dictionaries
	# startb - first address of bb
	def NewContext(self, var, startb):
		self.cdict[var] = {
			'varState': var + '@' + str(hex(startb)), 
			'dirty'   : False
		}

	#TODO: copy current ctx into new one
	def NewBranchContext(self, ctx):
		return None

	#TODO ?
	def ResetContext(self):
		return None

	def SearchInsn(self, r2, insn):
		return r2.cmdj("/cj " + insn)
	
	# Assumes already bb aligned.
	# Analyzes one block only. Call whenever traversing new bb along path
	# TODO: implement block
	def ContextBlockTrace(self, var, r2, block=None):
		block    = dict(item.split(': ') for item in r2.cmd('afbi').split('\n'))
		blocklen = int(block['ninstr'])
		for i in xrange(blocklen):
			instr = r2.cmdj('aoj')[0]
			self.handler.CallHandler(var, instr, self.cdict[var])
			r2.cmd('so')

		return self.cdict[var]['varState']

	#TODO: group similar contexts?
