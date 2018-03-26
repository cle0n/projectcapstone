import os
import argparse
import r2pipe

def RunCommand(r2, command):
    return r2.cmd(command) 

def Seeker(r2, symbol):
    r2.cmd("s " + symbol)
    return r2.cmd("s")

def OpenProgram(path):
    return r2pipe.open(path)


def CheckAllBranchesJ(r2, jump):
    loc = 0
    result = r2.cmdj("/cj cmp")

    if not result:
	print("No comparisons found!")
	return

    for line in result:
#	print(loc)
	diff = line["offset"] - loc
	loc = line["offset"]
	if diff < 4:
		continue
	if line["code"][0:4] != "cmp ":
		continue

	Seeker(r2, str(loc))
#	r2.cmdj("pdJ 2")[1]	
#	if r2.cmdj("pdJ 2")[1]["text"][-7:] == "invalid":
#		continue

	nextLines = r2.cmdj("aoj 2") #This is where that stupid "Oops" is coming from
	if len(nextLines) < 2:
		continue

	nextLine = nextLines[1]
	if nextLine["mnemonic"] == jump:
		print("")
		print("Control construct detected... (" + str(hex(loc)) + ")")
		addr = nextLine["addr"]
		dst = nextLine["jump"]
		if addr > dst:
			print("Loop detected")
		else:
			print("If detected")
		operands = nextLines[0]["opex"]["operands"]
		if operands[0]["type"] == "reg":
			print("OP1: Variable detected: " + operands[0]["value"])
		elif operands[0]["type"] == "imm":
			print("OP1: Immediate value detected: " + str(operands[0]["value"]))
		elif operands[0]["type"] == "mem":
			base = operands[0]["base"]
			scale = operands[0]["scale"]
			disp = operands[0]["disp"]
			if "index" in operands[0]:		
				index = operands[0]["index"]
				print("OP1: Memory value detected: [" + base + " + " + str(scale) + "*" + index + " + " + str(hex(disp)) + "]")
			else:
				print("OP1: Memory value detected: [" + base + " + " + str(hex(disp)) + "]")
		else:
			print("OP1: Type " + operands[0]["type"] + " detected")


		if operands[1]["type"] == "reg":
			print("OP2: Variable detected: " + operands[1]["value"])
		elif operands[1]["type"] == "imm":
			print("OP2: Immediate value detected: " + str(operands[1]["value"]))
		elif operands[1]["type"] == "mem":
                        base = operands[1]["base"]
                        scale = operands[1]["scale"]
                        disp = operands[1]["disp"]
                        if "index" in operands[1]:
                                index = operands[1]["index"]
                                print("OP2: Memory value detected: [" + base + " + " + str(scale) + "*" + index + " + " + str(hex(disp)) + "]")
                        else:
                                print("OP2: Memory value detected: [" + base + " + " + str(hex(disp)) + "]")
                else:
			print("OP2: Type " + operands[1]["type"] + " detected")
def CheckAllBranches(r2, jump):

    result = RunCommand(r2, "/c cmp");

    if not result:
        print("No comparisons found!")
	return 

    fresult = result.split("\n")
    for line in fresult:
	loc = line.split(" ")[0]
	cmp = line.split("cmp")[-1] #Assuming instruction is cmp, not cmpsb or something
	Seeker(r2, loc)
	nextTwoLines = r2.cmd("pd 2")
	nextLinesSplit = nextTwoLines.split("\n")
	nextLine = nextLinesSplit[-1]
	if len(nextLine.split(jump)) == 2:
	    jloc = nextLine.strip().split(" ")[1]
	    jdst = nextLine.split(jump)[-1].strip()
	    try:
		hjloc = int(jloc, 16)
		hjdst = int(jdst, 16)
		if hjloc > hjdst:
		    print("Loop detected and comparison found (" + loc + ")")
		    cmpvar1 = cmp.split(",")[0]
		    cmpvar2 = cmp.split(",")[1]
		    try:
			int(cmpvar2, 16)
			print("Variable detected: " + cmpvar1)
		    except ValueError:
			print("Variables detected: " + cmpvar1 + ", " + cmpvar2)
			
#		    print(line)
#		    print(nextLine)
	    except ValueError:
		print("Jump destination isn't an explicit number")
	
def CheckAllJumps(r2, jump):

    # "j[mg]" all jmp and jg/jge
    # if a regex is used the split output will differ
    result = RunCommand(r2, "/c " + jump)  

    if not result: 
        print("No loops found!")
        return

    fresult = result.split("\n")
    for line in fresult:
        loc = line.split(" ")[0]
        dst = line.split(jump)[-1].strip()
        try:
            hloc = int(loc, 16)
            hdst = int(dst, 16)
            if hloc > hdst:
                print(loc + ": Loop detected (" + loc + "->" + dst + ")")
        except ValueError:
            print(loc + ": Destination isn't an explicit number (" + dst + ")")

def Usage():
    print "Usage: ./program.py path instruction"
    exit()

if __name__ == '__main__':

    # Add commandline arguments here
    parser = argparse.ArgumentParser()
    parser.add_argument("arg", nargs='*')
    args   = parser.parse_args()

    if not args.arg:
        Usage()

    r2 = OpenProgram(os.path.realpath(args.arg[0]))
    r2.cmd("e search.flags=false") #Freakin search flags pollute pd results!

#    CheckAllJumps(r2, args.arg[1])
    CheckAllBranchesJ(r2, args.arg[1])	
    r2.quit()
