'''
	Voyager 1.

	notes:
	- be able to set a path search depth
	- be able to set paths to traverse
	- let the user be able to switch branches at any point
	- continue searching for paths from incomplete ones
	- be able to interactively modify or create paths if analysis fails
	- store paths on disk?
    - https://stackoverflow.com/questions/1388818/how-can-i-compare-two-lists-in-python-and-return-matches

	moar notes:
	- depending on call destination the paths being mapped may overlap or record
	  more than what is actually there. (ex. syscall, int, or calls (that have 
      relocs). The path is still correct however. This could be corrected 
      post-analysis

'''

from copy import copy

class Voyager:
	
	def __init__(self, r2):
		self.r2       = r2
		self.bbs      = r2.cmdj('afbj')

		self.pathlist = []
		self.looplist = []
		self.path     = 0
		self.node     = 0

	def ViewPaths(self):
		print ""
		for pathindex, path in enumerate(self.pathlist):
			print "PATH: %d" % (pathindex)
			for node in path:
				print str(hex(node))
			print ""

	def ViewLoops(self):
		print ""
		for loopindex, loop in enumerate(self.looplist):
			print "LOOP: %d" % (loopindex)
			for node in loop:
				print str(hex(node))
			print ""

	# Finds and sets first path offset is aligned with
	def OnFirstPath(self, offset):
		self.r2.cmd('sb ' + str(hex(offset)))
		bbp = int(self.r2.cmd('s'), 16)
		for pindex, path in enumerate(self.pathlist):
			if bbp in path:
				self.path = pindex
				self.node = path.index(bbp)
				break
		return int(self.r2.cmd("s"), 16)

	#TODO
	def SwitchBranch(self):
		return 0

	def SetPath(self, pathindex):
		self.path = pathindex
		self.node = 0

	def TotalPaths(self):
		return len(self.pathlist)

	def NextPathBlock(self):
		self.node += 1
		return self.r2.cmd('s ' + str(hex(self.pathlist[self.path][self.node])))

	def PrevPathBlock(self):
		self.node -= 1
		return self.r2.cmd('s ' + str(hex(self.pathlist[self.path][self.node])))

	def GetAddrIndex(self, addr):
		for i in xrange(len(self.bbs)):
			if self.bbs[i]['addr'] == addr:
				return i

	'''
		Call ONCE per instance/function (for now), like this:

		from voyager1 import Voyager
		...
		p = Voyager(r2)
		p.PathFinder([], p.bbs[0]['addr']) <-- assumes that entry0 is the first bb

		PATH : An empty list (see above)
		ADDR : Starting address (assumes it is bb aligned and an INT)
		DEPTH: #TODO
	'''
	def PathFinder(self, path, addr, depth=None):

		divergedFromLastLoop = True # Technically don't need this, but just to be safe

		todo = []
		loop = []

		todo.append(addr)

		while todo:
			node = todo.pop()
# This is where loop detection happens
# I have to keep track of the first time any node reappears in the path, look back in the path array until it appears again, and take note of that loop
# Then, stop keeping track of loops until the current node diverges from the loop that was just found, to avoid duplicate loops and extra work

			if node in path:  
				#print "Node in path!"

				if not self.looplist or node not in self.looplist[-1]:
					divergedFromLastLoop = True

				if divergedFromLastLoop:
					i = -1					
					while path[i] != node:
						loop.insert(0, path[i])
						i -= 1
					loop.insert(0, node)
					self.looplist.append(loop)
					loop = []
					divergedFromLastLoop = False

				path.append(node)

				continue

			path.append(node)

			index = self.GetAddrIndex(node)

			if 'fail' in self.bbs[index]:
				self.PathFinder(copy(path), self.bbs[index]['fail'])

			if 'jump' in self.bbs[index]:
				todo.append(self.bbs[index]['jump'])

		self.pathlist.append(path)
		

	#TODO
	#def PathsFromPoint(self):
	#def TracePath(self):
	#def BackTrace(self): ?
