#!/bin/bash
echo "This takes forever and shouldn't be interrupted.  Continue?"
echo "Press any key..."
read test

echo "Installing some pre-reqs from repos."
apt-get update
#apt-get upgrade
apt-get --ignore-missing install -y build-essential libpcap-dev udhcpd tmux byobu ettercap-text-only proxychains python-dev python-pypcap subversion git nano vim libnl-dev libssl-dev ruby ruby-dev sqlite3 libsqlite3-dev libsqlite3-ruby1.9.1 python-twisted

echo "Downloading Hostapd-Karma"
wget -O hostapd.tar.bz2 http://www.digininja.org/files/hostapd-1.0-karma.tar.bz2
echo "Unpacking"
tar xvf hostapd.tar.bz2
cd hostapd-1.0-karma/hostapd/
echo "Building"
make hostapd
echo "Installing"
mv hostapd ../../../bin/hostapd-karma
cd ../../

echo "Uninstalling libnl1 and replacing with libnl3"
apt-get install -y libnl-route-3-dev libnl-3-dev libnl-3-200 libnl-nf-3-200 libnl-nf-3-dev libnl-utils libnl-genl-3-200 libnl-genl-3-dev

echo "Downloading Pylibpcap"
wget -O pylibpcap.tar.gz 'https://downloads.sourceforge.net/project/pylibpcap/pylibpcap/0.6.4/pylibpcap-0.6.4.tar.gz?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fpylibpcap%2Ffiles%2Fpylibpcap%2F&ts=1372734756&use_mirror=iweb'
echo "Unpacking Install files..."
tar xvf pylibpcap.tar.gz
cd pylibpcap-0.6.4/
echo "Installing"
python setup.py install
cd ../
rm pylibpcap.tar.gz

echo "Downloading Lorcon"
git clone https://code.google.com/p/lorcon/
cd lorcon
echo "Starting install"
./configure
make
make install
echo "Symlinking proper directory for liborcon"
ln -s /usr/local/lib/liborcon2-2.0.0.so /usr/lib/liborcon2-2.0.0.so
echo "Finished Lorcon install, installing pyLorcon2"
cd pylorcon2
python setup.py install
echo "*******************************************************************"
echo "***************TEST LORCON/PYLORCON ON YOUR OWN NOW****************"
pwd
echo "*******************************************************************"

cd ../../
echo "Downloading py80211"
git clone https://code.google.com/p/py80211
cd py80211/
python setup.py install
echo "Finished installing py80211"
cd ../

echo "Downloading airdrop2"
git clone https://code.google.com/p/airdrop2/
cd airdrop2
#echo "Switching to Wifiobjects"
#git checkout wifiobjects
echo "Installing airdrop"
mv airdrop-immunizer.py ../../bin/airdrop-immunizer.py
cd ../
mv airdrop2/ ../bin/

echo "Installing some BEEF deps"
gem install bundler
cd ../bin/beef/
bundle install

echo "========================================="
echo "          FINISHED INSTALLATION          "
echo "========================================="
echo "If you have issues with properly starting the software stack, then something may have changed in the delicate balance of linux repositories and the large amounts of code that blend together to make this work."
echo "---"
echo "If you used the install script on a fresh install and it didn't work, send your list of installed packages, your distribution release, uname -a, and hw specs to @crypt0s (twitter) or file a bug report on sourceforge"
echo "---"
echo "Thanks for playing."
