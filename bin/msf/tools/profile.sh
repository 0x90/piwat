#!/bin/sh
CPUPROFILE_FREQUENCY=500 CPUPROFILE=profile.dat RUBYOPT="-r`gem which perftools | tail -1`" ruby msfcli z
pprof.rb --gif profile.dat > profile.gif
