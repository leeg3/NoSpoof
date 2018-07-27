#!/usr/bin/env python

"""
Authors: Greg Lee, An Nguyen
Date: 7/17/18
Description: This script is designed to look for ARPSpoofing which is a key step in order to execute a Man in the Middle Attack. If an attack is detected, then a notification is sent to the user.

Requirements:
1. python3
2. winpcap
3. netifaces, AppKit, scapy python modules

execute instructions:
sudo python3 Mac-detectARPSpoof.py


NOTE:

change error to alert if possible for log entry 
"""

import os, time, netifaces, sys, logging, subprocess, ctypes #, AppKit
import platform
from scapy.all import sniff

requests = []
replies_count = {}
notification_issued = []
required_modules = ["netifaces", "scapy", "AppKit"]

ipaddr = ""
broadcast = ""

request_threshold = 7


def MacSpoofScanner():
    # determine if user has root permissions
    if os.geteuid() != 0:
	       exit("Root permisson is needed to manage network interfaces. Aborting.")
    else:
        print("Current user has necessary permissions.")

    print("Info will be stored in a log titled \"ARP log - Mac.txt\"")

    # format log
    formatLog()

    # do scanner things

    macNotification("Spoof Notification", "Your networked is under attacked", "Detected from [MAC Address]")


    sniff(filter = "arp", prn = packet_filter, store = 0)



"""
def spoofChecker (source, mac, destintion):
    if destination == broastcast:
        if not mac in replies_count:
            replies_count[mac] = 0

    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1

        logging.warning("Request count {}".format(mac, replies_count[mac]))

        # Check whether or not number of replies reach a threshold and check for whether ir not the notification is already displayed
        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            # Log the attack to the log file
            logging.error("ARPSpoof Detected from MAC Address {}".format(mac))

            # if spoof detected, then issue a notification
            macNotification("Spoof Notification", "Your networked is under attacked", "Detected from {}.".format(mac))

            # Add to notification_issued list so that the notification won't be repeated.
            notification_issued.append(mac)
        else:
            if source in requests:
                requests.remove(source)
"""


def spoofChecker (source, mac, destination):
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0

    if not source in requests and source != ipaddr:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1

        logging.warning("Request count {}".format(mac, replies_count[mac]))

        # Check whether or not number of replies reach a threshold and check for whether ir not the notification is already displayed
        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            # Log the attack to the log file
            logging.error("ARPSpoof Detected from MAC Address {}".format(mac))

            # if spoof detected, then issue a notification
            macNotification("Spoof Notification", "Your networked is under attacked", "Detected from {}.".format(mac))

            # Add to notification_issued list so that the notification won't be repeated.
            notification_issued.append(mac)
    else:
        if source in requests:
            requests.remove(source)


def packet_filter (packet):
    # Retrieve necessary parameters from packet
    source = packet.sprintf("%ARP.psrc%")
    destination = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    op = packet.sprintf("%ARP.op%")
    if source == ipaddr:
        requests.append(destination)
    if op == 'is-at':
        return spoofChecker(source, source_mac, destination)


def formatLog():
    # define logging format
    logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename="ARP log - Mac.txt", filemode="a", level=logging.DEBUG)

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
        ipaddr = addrs[netifaces.AF_INET][0]["addr"]
        broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
    except KeyError:
        exit("Cannot read address/broadcast address on interface {}".format(interface))

def macNotification(title, subtitle, content):
    # init OS X notification center
    import AppKit

    notification_center = AppKit.NSUserNotificationCenter.defaultUserNotificationCenter()

    # create a new notification and set title, subtitle and content
    notification = AppKit.NSUserNotification.alloc().init()
    notification.setTitle_(title)
    notification.setSubtitle_(subtitle)
    notification.setInformativeText_(content)

    # display to user
    notification_center.deliverNotification_(notification)


def main():
    # get system OS
    system_os = platform.system()

    # Determine system OS and execute appropriate function
    if system_os == 'Darwin': # Mac
        # retrieve installed python modules
        #installed_modules = subprocess.check_output("pip freeze")

        #for elem in required_modules:
        #    if elem not in str(installed_modules):
        #        exit("Missing python modules. Please check to ensure that the required modules are installed.")

        # move permission checker here

        MacSpoofScanner()
    else:
        print("Operating System not supported. Please ensure that you have the correct script for your operating system.")



if __name__ == '__main__':
	main()
