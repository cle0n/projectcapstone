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
		#self.bbs = [{"jump":4209763,"fail":4209736,"addr":4208479,"size":1257,"inputs":1,"outputs":2,"ninstr":249,"traced":False},{"jump":4209763,"addr":4209736,"size":27,"inputs":1,"outputs":1,"ninstr":6,"traced":False},{"jump":4210355,"fail":4210283,"addr":4209763,"size":520,"inputs":2,"outputs":2,"ninstr":110,"traced":False},{"jump":4210355,"addr":4210283,"size":72,"inputs":1,"outputs":1,"ninstr":17,"traced":False},{"jump":4210573,"fail":4210515,"addr":4210355,"size":160,"inputs":2,"outputs":2,"ninstr":33,"traced":False},{"jump":4210573,"addr":4210515,"size":58,"inputs":1,"outputs":1,"ninstr":11,"traced":False},{"jump":4211677,"fail":4211646,"addr":4210573,"size":1073,"inputs":2,"outputs":2,"ninstr":214,"traced":False},{"jump":4211812,"fail":4211659,"addr":4211646,"size":13,"inputs":1,"outputs":2,"ninstr":2,"traced":False},{"jump":4211858,"fail":4211672,"addr":4211659,"size":13,"inputs":1,"outputs":2,"ninstr":2,"traced":False},{"jump":4211975,"addr":4211672,"size":5,"inputs":1,"outputs":1,"ninstr":1,"traced":False},{"jump":4211748,"fail":4211718,"addr":4211677,"size":41,"inputs":1,"outputs":2,"ninstr":10,"traced":False},{"jump":4211748,"addr":4211718,"size":30,"inputs":1,"outputs":1,"ninstr":6,"traced":False},{"jump":4211797,"fail":4211757,"addr":4211748,"size":9,"inputs":2,"outputs":2,"ninstr":2,"traced":False},{"jump":4211797,"addr":4211757,"size":40,"inputs":1,"outputs":1,"ninstr":7,"traced":False},{"jump":4211991,"addr":4211797,"size":15,"inputs":2,"outputs":1,"ninstr":3,"traced":False},{"jump":4211991,"addr":4211812,"size":46,"inputs":1,"outputs":1,"ninstr":8,"traced":False},{"jump":4211901,"fail":4211869,"addr":4211858,"size":11,"inputs":1,"outputs":2,"ninstr":3,"traced":False},{"jump":4211901,"addr":4211869,"size":32,"inputs":1,"outputs":1,"ninstr":6,"traced":False},{"jump":4211991,"addr":4211901,"size":74,"inputs":2,"outputs":1,"ninstr":15,"traced":False},{"jump":4211991,"addr":4211975,"size":16,"inputs":1,"outputs":1,"ninstr":4,"traced":False},{"jump":4212161,"fail":4212120,"addr":4211991,"size":129,"inputs":4,"outputs":2,"ninstr":25,"traced":False},{"jump":4212161,"addr":4212120,"size":41,"inputs":1,"outputs":1,"ninstr":9,"traced":False},{"jump":4212439,"fail":4212398,"addr":4212161,"size":237,"inputs":2,"outputs":2,"ninstr":44,"traced":False},{"jump":4212439,"addr":4212398,"size":41,"inputs":1,"outputs":1,"ninstr":9,"traced":False},{"jump":4213065,"fail":4213050,"addr":4212439,"size":611,"inputs":2,"outputs":2,"ninstr":124,"traced":False},{"jump":4213065,"addr":4213050,"size":15,"inputs":1,"outputs":1,"ninstr":3,"traced":False},{"jump":4214056,"fail":4213785,"addr":4213065,"size":720,"inputs":2,"outputs":2,"ninstr":142,"traced":False},{"addr":4213785,"size":13,"inputs":1,"outputs":0,"ninstr":2,"traced":False},{"jump":4214134,"addr":4214056,"size":78,"inputs":1,"outputs":1,"ninstr":16,"traced":False},{"jump":4208479,"fail":4214162,"addr":4214134,"size":28,"inputs":1,"outputs":2,"ninstr":5,"traced":False},{"jump":4214513,"fail":4214511,"addr":4214162,"size":349,"inputs":1,"outputs":2,"ninstr":72,"traced":False},{"jump":4214553,"addr":4214511,"size":2,"inputs":1,"outputs":1,"ninstr":1,"traced":False},{"jump":4214553,"addr":4214513,"size":40,"inputs":1,"outputs":1,"ninstr":7,"traced":False},{"jump":4215833,"fail":4215790,"addr":4214553,"size":1237,"inputs":2,"outputs":2,"ninstr":248,"traced":False},{"jump":4215833,"addr":4215790,"size":43,"inputs":1,"outputs":1,"ninstr":9,"traced":False},{"addr":4215833,"size":808,"inputs":2,"outputs":0,"ninstr":157,"traced":False}]

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
					#print "Loop found!"
					#print loop
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
