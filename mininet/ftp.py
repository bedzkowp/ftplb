#!/usr/bin/python

"""
Create a network and start ftpd on each host.  
"""
import sys
import os
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.node import Node, RemoteController
from mininet.util import waitListening
from ftptopo import FTPTopo

def FTPNet( f=3, h=2, **kwargs ):
  topo = FTPTopo( f, h )
  c0 = RemoteController( 'c0', ip='127.0.0.1', port=6653 )
  return Mininet( topo, controller=c0, **kwargs)

def ftpd( network ):
  network.start()

  path = os.path.dirname(os.path.abspath(__file__))
  info( "*** FTPs starting ***\n" )
  for host in network.hosts:
    if host.name.startswith( 'ftp' ):
      host.cmd( '/usr/sbin/vsftpd &' )# + path + '/ftp/vsftpd.conf &' ) 

  for host in network.hosts:
    if host.name.startswith( 'ftp' ):
      waitListening( client=host, port=21, timeout=5 )

  info( "*** FTPs started ***\n" )

  net.pingAll()

  CLI( network )

  for host in network.hosts:
    if host.name.startswith( 'ftp' ):
      host.cmd( 'kill %' + '/usr/sbin/vsftpd' )

  network.stop()

if __name__ == '__main__':
  print sys.argv
  lg.setLogLevel( 'info' )
  net = FTPNet( f=3, h=2 )
  ftpd(net)
