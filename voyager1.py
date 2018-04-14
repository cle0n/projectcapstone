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
		self.path     = 0
		self.node     = 0

	def ViewPaths(self):
		print ""
		for pathindex, path in enumerate(self.pathlist):
			print "PATH: %d" % (pathindex)
			for node in path:
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

		todo = []

		todo.append(addr)

		while todo:
			node = todo.pop()

			if node in path:
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
