"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class FTPTopo( Topo ):
    "Simple topology example."

    def __init__( self, f=3, h=2 ):
	"Create custom topo."

	Topo.__init__( self )
	
	ftp = []
	for i in range(f):
		num = str( i + 1 )
		ftp.append( self.addHost( 'ftp' + num, ip='10.0.1.' + num, mac='00:00:00:00:01:' + num ) )

	host = []
	for i in range(h):
		num = str( i + 1 )
		host.append( self.addHost( 'h' + num, ip='10.0.2.' + num, mac='00:00:00:00:02:' + num ) )

	leftSwitch = self.addSwitch( 's1' )
	rightSwitch = self.addSwitch( 's2' )

	for f in ftp:
		self.addLink( f, leftSwitch )

	for h in host:
		self.addLink( h, rightSwitch )
	
	self.addLink( leftSwitch, rightSwitch )

topos = { 'ftptopo': ( lambda f,h: FTPTopo(f,h) ) }
