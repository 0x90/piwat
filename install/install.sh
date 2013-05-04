#!/bin/bash

echo "This is going to take like 30 minutes and will not require user input after you press enter at the prompt"
echo "!!!!!!!!!!!!!!!!!!!!!!!WARNING!!!!!!!!!!!!!!!!!!"
echo " > This will change the default cpu/gpu memory split on your raspberry pi!"
echo " > This could cause graphics-intensive operations to suck."
echo " > This software package will not work without this change."
echo " > This script will replace python-libpcap with python-pypcap."

##############
#Configure Pi#
##############
echo "!!!!running beef and metasploit requires at least a 224/32 MB split!!!!"
echo "IF YOU PRESS \"Y\" YOU WILL BE CHANGING YOUR DEFAULT SPLIT TO 224/32"
echo "IF YOU HAVE A 512 MB PI, YOU MAY NOT NEED TO DO THIS."
echo ""
echo "press enter key to continue"
echo ""

read nothing

echo "Adjusting Memsplit"
mv /boot/config.txt /boot/config.txt.old
cp ../conf/config.txt /boot/config.txt

# The old way
#mv /boot/start.elf /boot/start.elf.old
#cp lib/arm224_start.elf /boot/start.elf

######################
#Aircrack/dump/things#
######################
echo "Installing precompiled aircrack libs/bins to save time"
cp lib/PyLorcon2.so /usr/lib/python2.7/PyLorcon2.so
cp lib/pylorcon.so /usr/lib/python2.7/pylorcon.so
cp lib/liborcon-1.0.0.so /usr/local/lib/liborcon.so
cp lib/liborcon2-2.0.0.so /usr/local/lib/liborcon2.so
cp lib/liborcon* /usr/local/lib/

###############################
#Install py80211, thx tehxile!#
###############################
#lib/py80211/setup.py config
#lib/py80211/setup.py install

#####################
#Install easy things#
#####################
echo "Updating package repositories"
apt-get update
echo "Installing packages"
apt-get --ignore-missing install -y build-essential udhcpd tmux byobu ettercap proxychains python-pypcap subversion git nano vim libnl1 ruby ruby-dev libsqlite3-dev
echo "Finished installing packages"

#this is stuff for beef
# I have edited the bundler gemfile junk to take the version of eventmachine that works on the raspi
# This took forever and I would reccomend fucking with it if you get stuck booting up beef
# Report this as a bug if it happens though
echo "Installing beef things"
gem install bundler
cd ../bin/beef/
bundle install
cd ../../install/

#enable the dhcpd stuff.
cp conf/udhcpd.default /etc/default/udhcpd

#get the right version of pylibpcap (according to documentation from Textile)
# Todo: download most things directly from source and compile or use (like beef/msf)
#pylibpcap airdrop2 dependancy
git clone https://github.com/signed0/pylibpcap.git
cd pylibpcap/
python setup.py install
cd ../

#py80211 tools (hey, i helped write that!)
git clone https://code.google.com/p/py80211/
cd py80211/
python setup.py install
cd ../

#Airdrop (hey, this too!)
git clone https://code.google.com/p/airdrop2/
cd airdrop2
python setup.py install
cd ../


echo ""
echo "!!!!!!!!If you had a bunch of bundler/ruby/gem errors just now, file a bug report!!!!!!!"
echo ""
