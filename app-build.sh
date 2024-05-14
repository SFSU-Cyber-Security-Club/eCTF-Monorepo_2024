#!/bin/sh
# I am way too lazy to have to type out this command over and over again, maybe this will work through a script
#ectf_build_ap -d . -on AP -od build -p 123456 -t TOKEN -c 1 -ids "0x11111124" -b "Good morning"
ectf_build_ap -d . -on AP -od build -p 123456 -t TOKEN -c 2 -ids "0x30b79d61, 0x11111125" -b "Good morning"
