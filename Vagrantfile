# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/xenial64"
  config.vm.hostname = "ftplb"
  config.vm.provision "docker" do |d|
    d.pull_images "onosproject/onos"
    d.run "onosproject/onos",
      auto_assign_name: false,
      args: "--name onos -p 6653:6653 -p 8181:8181 -v /vagrant/util/client.sh:/root/client.sh:ro"
  end
  config.vm.provision "shell", path: "util/provision.sh"
  config.vm.network "forwarded_port", guest: 8181, host: 8181
  config.vm.synced_folder ".", "/vagrant"
  config.vm.synced_folder "mininet/", "/home/vagrant/mininet"

end
