import r2pipe
from voyager1 import Voyager
r2 = r2pipe.open("/home/ian/projectcapstone/tests/outdir/nested")
r2.cmd("aaaa")
r2.cmd("s main")
p = Voyager(r2)
p.PathFinder([], p.bbs[0]['addr']) 
#p.ViewPaths()
p.ViewLoops()
