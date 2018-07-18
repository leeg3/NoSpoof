#!/usr/bin/env python

"""
Authors: Greg Lee, An Nguyen
Date: 7/17/18
Description: This script is designed to look for ARPSpoofing which is a key step in order to execute a Man in the Middle Attack. If an attack is detected, then a notification is sent to the user.

execute instructions:
sudo python3 detectARPSpoof.py

"""

import os, time, netifaces, sys, logging, ctypes, win10toast 
# import os, time, sys, logging
import platform
from scapy.all import sniff

requests = []
replies_count = {}
notification_issued = []

def MacSpoofScanner():
    # determine if user has root permissions
    if os.geteuid() != 0:
	       exit("Root permisson is needed to manage network interfaces. Aborting.")
    else:
        print("Current user has necessary permissions.")

    # format log
    formatLog()

    # do scanner things


    # if spoof detected, then issue a notification
    macNotification()


def getAccountPrivilegesWindows():
    if ctypes.windll.shell32.IsUserAnAdmin() != 0:
        exit("Admin permission is needed to manage network interfaces. Aborting.")
    else:
        print("Current user has necessary permisisons.")

    formatLog()


def formatLog():
    # define logging format
    logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename="ARP log.txt", filemode="a", level=logging.DEBUG)

    # import available network interfaces
    available_interfaces = netifaces.interfaces()

    # Ask user for desired interface
    interface = input("Please select the interface you wish to use. {}\n".format(str(available_interfaces)))

    # Check if specified interface is valid
    if not interface in available_interfaces:
        exit("Interface {} not available.".format(interface))

    # Retrieve network addresses (IP, broadcast) from the network interfaces
    addrs = netifaces.ifaddresses(interface)
    try:
        local_ip = addrs[netifaces.AF_INET][0]["addr"]
        broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
    except KeyError:
        exit("Cannot read address/broadcast address on interface {}".format(interface))

def macNotification(title, subtitle, content):
    # init OS X notification center
    notification_center = AppKit.NSUserNotificationCenter.defaultUserNotificationCenter()

    # create a new notification and set title, subtitle and content
    notification = AppKit.NSUserNotification.alloc().init()
    notification.setTitle_(title)
    notification.setSubtitle_(subtitle)
    notification.setInformativeText_(content)

    # display to user
    notification_center.deliverNotification_(notification)


def main():

    system_os = platform.system()

    # Determine system OS and execute appropriate function
    if system_os == 'Darwin': # Mac
        MacSpoofScanner()
    elif system_os == 'Windows': # Windows
        getAccountPrivilegesWindows()
    else:
        print("Operating System not supported")

    # retrieve log name from user
    # log_name = input("Enter a name for the log file: ")

    # if no user input then file will be called ARP log.txt
    # if log_name == "":
    print("Info will be stored in a log titled \"ARP log.txt\"")
    #    log_name = "ARP log.txt"



if __name__ == '__main__':
	main()
