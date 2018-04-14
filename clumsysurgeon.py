import os
import argparse
import r2pipe

from   eyeofsauron import EyeOfSauron
from   voyager1    import Voyager


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument("arg", nargs='*')
	args   = parser.parse_args()

	if not args.arg:
		print "USAGE: clumsysurgeon.py [infile]"
		exit(1)

	r2 = r2pipe.open(os.path.realpath(args.arg[0]))
	r2.cmd("aaaa")

	flag1 = False
	flag2 = False
	flag3 = False

	e = EyeOfSauron()
	p = Voyager(r2)
	p.PathFinder([], p.bbs[0]['addr'])

	cpuidLocs = e.SearchInsn(r2, "cpuid")
	for cpuidInstr in cpuidLocs:
		cpuidInstrLoc = cpuidInstr["offset"]
		# keep offsets/addr as numbers when passing to Voyager or EyeOfSauron
		start  = p.OnFirstPath(cpuidInstrLoc)
		finish = r2.cmdj("pdbj")[-1]["offset"]

		# need to backtrace eax if its not in the block "cpuid" is in
		e.NewContext('eax', start)
		eaxVal = e.ContextBlockTrace('eax', r2)
		
		if eaxVal == "1":
			print "eax is one when CPUID is called"
			flag1 = True

		btLocs = e.SearchInsn(r2, "bt")
		for btInstr in btLocs:
			btInstrLoc = btInstr["offset"]
			# TODO:
			# -  remove start and finish. Can't trust offset of "bt" to be after 
			#    "cpuid" offset, need to backtrack along path
			# 1. Seek to path block containing "bt"
			# 2. Verify "bt" is aligned within block
			# 3. Backtrace until "cpuid" is found. Can then assume "bt" is after
			#    "cpuid"
			if start <= btInstr["offset"] and btInstr["offset"] <= finish:
				#TODO: Seeking should be handled by Voyager to keep sync with r2
				#      session and block
				r2.cmd("s " + str(hex(btInstrLoc)))
				btInstrDetails = r2.cmdj("aoj")[0]
				if (
					btInstrDetails["opex"]["operands"][0]["type"] == "reg" and 
					btInstrDetails["opex"]["operands"][0]["value"] == "ecx" and
					btInstrDetails["opex"]["operands"][1]["type"] == "imm" and
					btInstrDetails["opex"]["operands"][1]["value"] == 31
				):
					print "31st bit of ecx being checked"
					flag2 = True

				e.NewContext('ecx', cpuidInstrLoc)
				ecxVal = e.ContextBlockTrace('ecx', r2)

				if ecxVal == "ecx@" + str(hex(cpuidInstrLoc)):
					print "ecx is unchanged between cpuid and bt commands"
					flag3 = True

				if flag1 and flag2 and flag3:
					print "VM detection code found!"
					print "cpuid location: " + str(hex(cpuidInstrLoc))
					print "bt location: " + str(hex(btInstrLoc))
					flag2 = False #Reset these for the next bt instruction, in case there are a few to check
					flag3 = False	
	r2.quit()












