#!/usr/bin/env python

"""
Authors: Greg Lee, An Nguyen
Date: 7/17/18
Description: This script is designed to look for ARPSpoofing which is a key step in order to execute a Man in the Middle Attack. If an attack is detected, then a notification is sent to the user.

execute instructions:
sudo python3 detectARPSpoof.py

"""

# import os, time, netifaces, sys, logging
import os, time, sys, logging
from sys import platform
# from scapy.all import sniff


def getAccountPrivileges():
    if os.geteuid() != 0:
	       exit("Root permisson is needed to interact with network interfaces. \nNow Aborting.")
    else:
        print("Current user has necessary permission.")

def main():

    # on mac get account privileges
    getAccountPrivileges()

    # retrieve log name from user
    # log_name = input("Enter a name for the log file: ")

    # if no user input then file will be called ARP log.txt
    # if log_name == "":
    print("Info will be stored in a log titled \"ARP log.txt\"")
    #    log_name = "ARP log.txt"







if __name__ == '__main__':
	main()
