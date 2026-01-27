lang en_US.UTF-8
keyboard us
timezone UTC --isUtc
rootpw packetfence
reboot

network --bootproto=static --ip=192.168.2.30 --netmask=255.255.255.0 --gateway=192.168.2.1 --nameserver=192.168.2.1 --hostname=packetfence.local

firewall --enabled
selinux --disabled

autopart
clearpart --all --initlabel

%packages
packetfence
%end
