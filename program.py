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

def CheckAllJumps(r2, jump):

    # "j[mg]" all jmp and jg/jge
    # if a regex is used the split output will differ
    result = RunCommand(r2, "/c/ " + jump)  

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

    CheckAllJumps(r2, args.arg[1])

    r2.quit()
