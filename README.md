```
CLI ONOS i instalacja apki:

portfel@black:~/ftplb$ vagrant up
(...)

portfel@black:~/ftplb$ vagrant ssh
vagrant@ftplb:~$ 
vagrant@ftplb:~$ onos apps -a -s
Logging in as karaf
*   9 org.onosproject.drivers              2.0.0.SNAPSHOT Default Drivers
*  15 org.onosproject.optical-model        2.0.0.SNAPSHOT Optical Network Model
*  42 org.onosproject.hostprovider         2.0.0.SNAPSHOT Host Location Provider
*  43 org.onosproject.lldpprovider         2.0.0.SNAPSHOT LLDP Link Provider
*  44 org.onosproject.openflow-base        2.0.0.SNAPSHOT OpenFlow Base Provider
*  45 org.onosproject.openflow             2.0.0.SNAPSHOT OpenFlow Provider Suite
* 158 org.onosproject.fwd                  2.0.0.SNAPSHOT Reactive Forwarding
vagrant@ftplb:~$ 
vagrant@ftplb:~$ onos-app 127.0.0.1 install /vagrant/onos-app-oneping-1.14.0-SNAPSHOT.oar 
{"name":"org.onosproject.oneping","id":181,"version":"1.14.0.SNAPSHOT","category":"Monitoring","description":"One-Ping-Only sample application","readme":"One-Ping-Only sample application","origin":"ON.Lab","url":"http://onosproject.org","featuresRepo":"mvn:org.onosproject/onos-app-oneping/1.14.0-SNAPSHOT/xml/features","state":"INSTALLED","features":["onos-app-oneping"],"permissions":[],"requiredApps":["org.onosproject.fwd"]}
vagrant@ftplb:~$ 
vagrant@ftplb:~$ onos app activate org.onosproject.oneping
Logging in as karaf
Activated org.onosproject.oneping
vagrant@ftplb:~$ 
vagrant@ftplb:~$ onos apps -a -s
Logging in as karaf
*   9 org.onosproject.drivers              2.0.0.SNAPSHOT Default Drivers
*  15 org.onosproject.optical-model        2.0.0.SNAPSHOT Optical Network Model
*  42 org.onosproject.hostprovider         2.0.0.SNAPSHOT Host Location Provider
*  43 org.onosproject.lldpprovider         2.0.0.SNAPSHOT LLDP Link Provider
*  44 org.onosproject.openflow-base        2.0.0.SNAPSHOT OpenFlow Base Provider
*  45 org.onosproject.openflow             2.0.0.SNAPSHOT OpenFlow Provider Suite
* 158 org.onosproject.fwd                  2.0.0.SNAPSHOT Reactive Forwarding
* 181 org.onosproject.oneping              1.14.0.SNAPSHOT One-Ping-Only App
vagrant@ftplb:~$ 
vagrant@ftplb:~$ 



Topoplogia w miniet:

vagrant@ftplb:~$ 
vagrant@ftplb:~$ sudo mininet/ftp.py 
['mininet/ftp.py']
*** Creating network
*** Adding controller
*** Adding hosts:
ftp1 ftp2 ftp3 h1 h2 
*** Adding switches:
s1 s2 
*** Adding links:
(ftp1, s1) (ftp2, s1) (ftp3, s1) (h1, s2) (h2, s2) (s1, s2) 
*** Configuring hosts
ftp1 ftp2 ftp3 h1 h2 
*** Starting controller
c0 
*** Starting 2 switches
s1 s2 ...
*** FTPs starting ***
.*** FTPs started ***
*** Ping: testing ping reachability
ftp1 -> ftp2 ftp3 h1 h2 
ftp2 -> ftp1 ftp3 h1 h2 
ftp3 -> ftp1 ftp2 h1 h2 
h1 -> ftp1 ftp2 ftp3 h2 
h2 -> ftp1 ftp2 ftp3 h1 
*** Results: 0% dropped (20/20 received)
*** Starting CLI:
mininet> 
mininet> h1 touch testfile
mininet> 
mininet> h1 ftp ftp1
Connected to 10.0.1.1.
220 (vsFTPd 3.0.3)
Name (10.0.1.1:vagrant): ftp
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd data
250 Directory successfully changed.
ftp> pust
?Invalid command
ftp> put testfile
local: testfile remote: testfile
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-------    1 111      116             0 Nov 27 14:02 testfile
226 Directory send OK.
ftp> exit
221 Goodbye.
mininet> 
```
