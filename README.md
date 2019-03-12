# myadb_interface

use adb command in my code 

demo is in window, so is linux

compile:

g++ -m32 -I "api" -o myadb.exe "main.cpp" -L. -l "AdbWinApi"

IMPORTANT:

there should no other adb, if there is please kill-erver first use the adb existing

run: 

myadb.exe
