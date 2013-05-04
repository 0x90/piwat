#./prep wlan0
#bin/airodump-ng wlan0 -w test --output-format csv
bin/airdrop-old.py -i wlan0 -r oldrule -t test-01.csv

