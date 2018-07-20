#   INSTRUCTION HOOK CALLBACKS
#
#   The last thing each hook should do is single step
###################################################################################
class InsnHooks:
	def __init__(self):
		self.IHOOKS = {
			'call' : self.HOOK_CALL,
			'ret'  : self.HOOK_RET,
			'cpuid': self.HOOK_CPUID,
			'bt'   : self.HOOK_BT,
			'push' : self.HOOK_PUSH,
			'jne'  : self.HOOK_JMP,
			'je'   : self.HOOK_JMP,
			'jge'  : self.HOOK_JMP,
			'jg'   : self.HOOK_JMP,
			'jle'  : self.HOOK_JMP,
			'jl'   : self.HOOK_JMP,
			'jae'  : self.HOOK_JMP,
			'jl'   : self.HOOK_JMP,
			'jle'  : self.HOOK_JMP,
			'jb'   : self.HOOK_JMP,
			'jbe'  : self.HOOK_JMP,
			'jo'   : self.HOOK_JMP,
			'jno'  : self.HOOK_JMP,
			'jz'   : self.HOOK_JMP,
			'jnz'  : self.HOOK_JMP,
			'js'   : self.HOOK_JMP,
			'jns'  : self.HOOK_JMP,
		}

	def HOOK_CALL(self, emuinfo, insn):

		expected_ret_val = hex(insn[0]['addr'] + insn[0]['size'])
		expected_esp_val = emuinfo.r2.cmd('ar esp')

		emuinfo.ret_stk.append([expected_ret_val, expected_esp_val])
		
		if emuinfo.verbosity > 1:
			print "! EXPECTED RETURN: " + expected_ret_val

		emuinfo.r2.cmd('s eip')

		if emuinfo.verbosity > 1:
			print emuinfo.r2.cmd('pd 1')

		emuinfo.r2.cmd('aes')
		return 1

	def HOOK_RET(self, emuinfo, insn):
		ret_val = hex(emuinfo.r2.cmdj('pxwj @ esp')[0])

		if emuinfo.verbosity > 1:
			print "! RET " + ret_val

		if emuinfo.ret_stk:
			expected         = emuinfo.ret_stk.pop()
			expected_ret_val = expected[0]
			expected_esp_val = expected[1]
			#expected_ret_val = emuinfo.ret_stk.pop()

			if expected_ret_val != ret_val:
				print "! UNEXPECTED RETURN (LIKELY STACK MANIPULATION)"
				print "  > EXPECTED: " + expected_ret_val
				print "  > ACTUAL  : " + ret_val

				if emuinfo.ctf:
					proceed = 'y'
				else:
					proceed = raw_input("Proceed to expected return address? (y/n): ")

				if proceed.lower() == 'y':
					print("Proceeding to expected return")
					emuinfo.r2.cmd('s ' + expected_ret_val)
					emuinfo.r2.cmd('-ar*; ar esp=' + expected_esp_val + '; aeip')
					print "eip = " + emuinfo.r2.cmd('ar eip') + " seed_addr = " + emuinfo.r2.cmd('s')
					return 1
			else:
				if emuinfo.verbosity > 1:
					print "! VALID RETURN"

		emuinfo.r2.cmd('aes')
		return 1

	def HOOK_BT(self, emuinfo, insn):
		ecx_val = int(emuinfo.r2.cmd('ar ecx'), 0)
		if ecx_val == emuinfo.CONTEXT['CPUID']['ecx']:
			print "! ECX UNCHANGED SINCE LAST CPUID CALL"
			btInstrDetails = emuinfo.r2.cmdj('aoj @ eip')[0]
			if (
				btInstrDetails['opex']['operands'][0]['type']  == 'reg' and
				btInstrDetails['opex']['operands'][0]['value'] == 'ecx' and
				btInstrDetails['opex']['operands'][1]['type']  == 'imm' and
				btInstrDetails['opex']['operands'][1]['value'] == 31
			):
				print "! 31st bit of ECX being checked"
				print "! VM DETECTION CODE FOUND"
		emuinfo.r2.cmd('aes')
		return 1

	def HOOK_CPUID(self, emuinfo, insn):
		eax_val = int(emuinfo.r2.cmd('ar eax'), 0)
		if eax_val == 1:
			print "! CPUID RUN WHERE EAX = 1"
			emuinfo.r2.cmd('aes')
			ecx_val = int(emuinfo.r2.cmd('ar ecx'), 0)
			emuinfo.CONTEXT['CPUID'] = {
				'eax': eax_val,
				'ecx': ecx_val,
			}
		else:
			emuinfo.r2.cmd('aes')
		return 1
	
	def HOOK_PUSH(self, emuinfo, insn):
		if emuinfo.pushes == 0:
			emuinfo.pushes = 1
			emuinfo.r2.cmd('s eip')
			while True:
				emuinfo.r2.cmd('so')
				instr = emuinfo.r2.cmdj('pdj 1')[0]
				if instr['type'] not in ['push', 'upush']:
					if instr['type'] not in ['call', 'ucall']:
						emuinfo.pushes = 0
					break
				emuinfo.pushes += 1 
		return 0

	def HOOK_JMP(self, emuinfo, insn):
		if emuinfo.loop_detected:
			if insn[0]['addr'] == emuinfo.loop_detected:
				if emuinfo.ctf:
					skip = 'y'
				else:
					skip = raw_input("Skip loop? (y/n): ")
				if skip.lower() == 'y':
					if emuinfo.verbosity > 1:
						print "Loop skipped"
					emuinfo.r2.cmd('s eip; so; aeip')
					emuinfo.jmp_stk['count'] = {}
					emuinfo.jmp_stk['order'] = []
					emuinfo.loop_detected = False
					return 1

		if insn[0]['addr'] in emuinfo.jmp_stk['count']:
			#emuinfo.loop_dectected = True
			if emuinfo.verbosity > 1:		
				print "Loop detected!"
			if emuinfo.jmp_stk['count'][insn[0]['addr']]+1 not in emuinfo.jmp_stk['count'].values():
				if emuinfo.verbosity > 1:		
					print "Top of loop detected!"

				if emuinfo.jmp_stk['count'][insn[0]['addr']] > 4:  # Jump count threshold = 4
					if emuinfo.verbosity > 1:
						print "Loop:"
					for addr in emuinfo.jmp_stk['order']: # Make sure to use 'order' array to retrieve jumps in order ('count' dictionary doesn't keep order info)
						if emuinfo.jmp_stk['count'][addr] == emuinfo.jmp_stk['count'][insn[0]['addr']]:
							if emuinfo.verbosity > 1:
								print hex(addr)
							emuinfo.loop_detected = addr # This will be populated with the last address once the loop is done. Skip this address!
			emuinfo.jmp_stk['count'][insn[0]['addr']] += 1
			
			#print emuinfo.jmp_stk
			emuinfo.r2.cmd('aes')
			return 1
		else:
			emuinfo.jmp_stk['count'][insn[0]['addr']] = 1
			emuinfo.jmp_stk['order'].append(insn[0]['addr'])

		emuinfo.r2.cmd('aes')
		return 0
	
