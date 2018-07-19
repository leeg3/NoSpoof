#!/usr/bin/env python

"""
Authors: Greg Lee, An Nguyen
Date: 7/17/18
Description: This script is designed to look for ARPSpoofing which is a key step in order to execute a Man in the Middle Attack. If an attack is detected, then a notification is sent to the user.

execute instructions:
sudo python3 detectARPSpoof.py

"""

import os, time, netifaces, sys, logging, ctypes #, AppKit
# import os, time, sys, logging
import platform
from scapy.all import sniff

requests = []
replies_count = {}
notification_issued = []

ipaddr = ""
broadcast = ""

def MacSpoofScanner():
    # determine if user has root permissions
    if os.geteuid() != 0:
	       exit("Root permisson is needed to manage network interfaces. Aborting.")
    else:
        print("Current user has necessary permissions.")

    print("Info will be stored in a log titled \"Mac ARP log.txt\"")

    macNotification("TEST", "TEST", "THIS IS A TESET")
    
    # format log
    formatLog()

    # do scanner things
    sniff(filter = "arp", prn = packet_filter, store = 0)

    # if spoof detected, then issue a notification
    macNotification()


def check_spoof (source, mac, destination):
    # Function checks if a specific ARP reply is part of an ARP spoof attack or not
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0

    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1
        # Logs ARP Reply
        logging.warning("ARP replies detected from MAC {}. Request count {}".format(mac, replies_count[mac]))

        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            # Check number of replies reaches threshold or not, and whether or not we have sent a notification for this MAC addr
            logging.error("ARP Spoofing Detected from MAC Address {}".format(mac)) # Logs the attack in the log file
            # Issue OS Notification
            macNotification("ARP Spoofing Detected", "The current network is being attacked.", "ARP Spoofing Attack Detected from {}.".format(mac))
            # Add to sent list to prevent repeated notifications.
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
        return check_spoof (source, source_mac, destination)


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
        ipaddr = addrs[netifaces.AF_INET][0]["addr"]
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



if __name__ == '__main__':
	main()
