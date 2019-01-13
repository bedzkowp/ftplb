#!/bin/sh
set -e

sed -i -e 's|http://archive.ubuntu.com/ubuntu|http://ftp.icm.edu.pl/pub/Linux/ubuntu/|g' /etc/apt/sources.list

systemctl mask openvswitch-testcontroller.service

DEBIAN_FRONTEND=noninteractive apt-get -y -q update
DEBIAN_FRONTEND=noninteractive apt-get install -y -q tree tmux tcpdump nmap mininet vsftpd openvswitch-testcontroller curl jq python-ipaddress python-requests arping

systemctl unmask openvswitch-testcontroller.service
systemctl disable openvswitch-testcontroller.service

systemctl stop vsftpd.service
systemctl disable vsftpd.service

cp /vagrant/util/conf/vagrant.mount /etc/systemd/system/vagrant.mount
cp -R /vagrant/util/conf/docker.service.d /etc/systemd/system/docker.service.d

chown root:root /vagrant/util/conf/vagrant.mount
chmod 644 /vagrant/util/conf/vagrant.mount
chown -R root:root /vagrant/util/conf/docker.service.d
chmod 644 /vagrant/util/conf/docker.service.d/vagrant.conf

systemctl daemon-reload

cp /vagrant/util/conf/vsftpd.conf /etc/vsftpd.conf
chown root:root /etc/vsftpd.conf
chmod 644 /etc/vsftpd.conf
mkdir -p /srv/ftp/data
chown ftp:ftp /srv/ftp/data

ln -sf /vagrant/util/onos /usr/local/bin/onos

mkdir /tmp/onosapp
docker cp onos:/root/onos/bin/_find-node /tmp/onosapp/
docker cp onos:/root/onos/bin/_rest-port /tmp/onosapp/
docker cp onos:/root/onos/bin/onos-app /tmp/onosapp/

head -1 /tmp/onosapp/onos-app >> /tmp/onosapp/onos-app-full
sed -e '/^#/d' /tmp/onosapp/_find-node  >> /tmp/onosapp/onos-app-full
sed -e '/^#/d' /tmp/onosapp/_rest-port >> /tmp/onosapp/onos-app-full
sed -e '/^#/d' /tmp/onosapp/onos-app | grep -v '. $(dirname $0)/_rest-port' | grep -v '. $(dirname $0)/_find-node' >> /tmp/onosapp/onos-app-full
cp /tmp/onosapp/onos-app-full /usr/local/bin/onos-app
chmod 755 /usr/local/bin/onos-app
rm -fr /tmp/onosapp

docker exec -t onos /root/client.sh app activate org.onosproject.fwd org.onosproject.openflow

oar_url=$(curl -s https://api.github.com/repos/bedzkowp/ftplb/releases/latest | jq --raw-output '.assets[0] | .browser_download_url')

wget $oar_url

/usr/local/bin/onos-app 127.0.0.1 install "${oar_url##*/}"

docker exec -t onos /root/client.sh app activate pl.edu.pw.ftplb
