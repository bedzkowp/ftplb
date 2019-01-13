#!/usr/bin/env python
import ftplib
import os
import time
import ipaddress
import string
import random
import sys
import time
import unittest

TMP_PATH = '/tmp'
TMP_FILE_SIZE_KB = 4096
TIMEOUT = 10
FTP_DATADIR = 'data'
FTP_LOGIN = 'ftp'

def random_str(length):
  return ''.join(random.sample(''.join([string.digits,string.letters]), length))


def close(ftp):
  ftp.quit()


def connect(ip, close=False):
  ipv4 = ipaddress.IPv4Address(unicode(ip))
  ftp = ftplib.FTP()
  ftp.connect(ip, timeout=TIMEOUT)
  banner = ftp.getwelcome()
  banner_ip = banner.split()[2].split(':')[1]
  ftp.login(FTP_LOGIN)

  if close:
    ftp.quit()

  return banner_ip, ftp


def get_file(ftp, fname):
  ftppath = FTP_DATADIR + '/' + fname
  ftp.retrbinary('RETR ' + ftppath, open(fname, 'wb').write)


def put_file(ftp, fname=None):
  if not fname:
    fname = 'autotest_' + random_str(5) + '.dat'
    path = TMP_PATH + '/' + fname
    with open(path, 'wb') as f:
      f.write(os.urandom(TMP_FILE_SIZE_KB))
  ftppath = FTP_DATADIR + '/' + fname
  ftp.storbinary('STOR ' + ftppath, open(path, 'rb'))

  return fname, ftp


def do_file_transfer(ip):
  banner_ip, ftp = connect(ip)
  fname, _ = put_file(ftp)
  get_file(ftp, fname)
  close(ftp)
  return True


def do_connect_close(ip):
  banner_ip, _ = connect(ip, close=True) 
  return banner_ip



class TestServerPool(unittest.TestCase):

  def setUp(self):
    global targets
    self.targets = targets

  def test_connect(self):
    #if len(targets) > 2:
    #  targets[2] = '121.0.0.1'
    for target in self.targets:
      self.assertEqual(do_connect_close(str(target)), str(target))

  def test_file_transfer(self):
    for target in self.targets:
      self.assertTrue(do_file_transfer(str(target)))


class TestVirtualIP(unittest.TestCase):

  def setUp(self):
    global targets
    global virtual_ip
    self.targets = targets
    self.virtual_ip = virtual_ip

    self._started_at = time.time()

  def tearDown(self):
    elapsed = time.time() - self._started_at
    print('{} ({}s)'.format(self.id(), round(elapsed, 2)))

  def test_connect(self):
    self.assertIn(do_connect_close(str(self.virtual_ip)), map(str, self.targets))

  def test_file_transfer(self):
    self.assertTrue(do_file_transfer(str(self.virtual_ip)))

  # @unittest.expectedFailure
  def test_connect_sequential_target_change(self):
    prev_banner_ip = '0.0.0.0'
    for i in range(3):
      banner_ip = do_connect_close(str(self.virtual_ip))
      self.assertNotEqual(prev_banner_ip, banner_ip)
      # self.assertIn(banner_ip, map(str, self.targets))
      prev_banner_ip = banner_ip

  # @unittest.expectedFailure
  def test_connect_concurrent_target_change(self):
    banner_ips = []
    ftps = []
    for i in range(3):
      banner_ip, ftp = connect(str(self.virtual_ip)) 
      banner_ips.append(banner_ip)
      ftps.append(ftp)

    map(close, ftps)
    
    print(banner_ips)

    for i in range(1, len(banner_ips)):
      self.assertNotEqual(banner_ips[i-1], banner_ips[i])
     
    

if __name__ == "__main__":
  
  global targets
  global virtual_ip

  if 'FTPLB_IPS' in os.environ:
    targets = [ipaddress.IPv4Address(unicode(ip)) for ip in os.environ['FTPLB_IPS'].split()]
  else:
    targets = [ipaddress.IPv4Address(unicode(ip)) for ip in [u'127.0.0.1']]

  if 'FTPLB_VIP' in os.environ:
    virtual_ip = ipaddress.IPv4Address(unicode(os.environ['FTPLB_VIP']))

  #for target in targets:
  #  do_connect_close(str(target))
# suite = unittest.TestLoader().loadTestsFromTestCase(TestStringMethods)
# unittest.TextTestRunner(verbosity=2).run(suite)
  unittest.main()


  

#  for target in targets:
#    file_transfer(str(target))
