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
import time
import requests
import ipaddress
import json

def FTPNet( f=3, h=2, **kwargs ):
  topo = FTPTopo( f, h )
  c0 = RemoteController( 'c0', ip='127.0.0.1', port=6653 )
  return Mininet( topo, controller=c0, **kwargs)

def ftpd( network ):
  network.start()

  path = os.path.dirname(os.path.abspath(__file__))
  info( '*** FTPs starting ***\n' )
  for host in network.hosts:
    if host.name.startswith( 'ftp' ):
      cfname = '/tmp/vsftpd-' + host.name + '.conf'
      host.cmd( 'cp /etc/vsftpd.conf ' + cfname )
      host.cmd( 'echo "ftpd_banner=FTPLB_NAME:' + host.name + ' FTPLB_IP:' + host.IP() + '" >> ' + cfname)
      info( '*** FTP: ' +  host.name + ' ' + host.IP() + ' conf: ' + cfname + '\n' )
      host.cmd( '/usr/sbin/vsftpd ' + cfname + ' &' ) # + path + '/ftp/vsftpd.conf &' ) 

  for host in network.hosts:
    if host.name.startswith( 'ftp' ):
      waitListening( client=host, port=21, timeout=5 )

  info( '*** FTPs started ***\n' )

  net.pingAll()

  if '--cli' in sys.argv:
    CLI( network )
  else:
    info( '*** TEST ***\n\n' )
    # time.sleep(5)
    run_tests( network )
    

  for host in network.hosts:
    if host.name.startswith( 'ftp' ):
      host.cmd( 'kill %' + '/usr/sbin/vsftpd' )

  network.stop()

def run_tests( network ):

  API_URL = 'http://localhost:8181/onos/ftp/'
  API_AUTH = ('onos', 'rocks')

  def get(endpoint):
    r = requests.get(API_URL + endpoint, auth=API_AUTH)
    assert r.status_code == 200, 'Failed API request {} status code: {}'.format(endpoint, r.status_code)
    return r.json()

  def put(endpoint, data=None):
    r = requests.put(API_URL + endpoint, auth=API_AUTH, data=json.dumps(data))
    assert r.status_code == 200, 'Failed API request {} status code: {}'.format(endpoint, r.status_code)
    return r.content
    

  def delete(endpoint):
    r = requests.delete(API_URL + endpoint, auth=API_AUTH)
    assert r.status_code == 200, 'Failed API request {} status code: {}'.format(endpoint, r.status_code)
    return r.content


  def get_sharedaddr():
    data = get('sharedaddr')
    ip = ipaddress.IPv4Address(data[u'sharedAddress'])
    return ip

  def put_sharedaddr(ip):
    put('sharedaddr/' + str(ip))

  def get_servers():
    data = get('servers')
    servers = map(ipaddress.IPv4Address, data[u'servers'])
    return servers

  def clear_servers():
    servers = get_servers()
    for server in servers:
      delete('servers/' + str(server))

  def put_server(ip):
    put('servers/' + str(ip))
 
      
  

  servers = filter( lambda x: x.name.startswith( 'ftp' ), network.hosts)
  clients = filter( lambda x: x.name.startswith( 'h' ), network.hosts)
  # print(servers)
  # print(clients)
 
  clear_servers()
  map(lambda s: put_server(s.IP()), servers)
  put_sharedaddr('10.0.1.99')

  time.sleep(1)
  for client in clients:
    info( '--- Tests for: {} - {} ---\n'.format( client.name, client.IP() ))
    print(client.cmd( 'FTPLB_VIP="{}" FTPLB_IPS="{}" /usr/bin/python /home/vagrant/mininet/test.py -vv'.format( get_sharedaddr(), ' '.join([s.IP() for s in servers]) )))

if __name__ == '__main__':
  print sys.argv
  lg.setLogLevel( 'info' )
  net = FTPNet( f=3, h=2 )
  ftpd(net)
