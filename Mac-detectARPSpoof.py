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
"""

# netifaces to get network interfaces.
import os, time, netifaces, sys, logging, subprocess, ctypes, AppKit
import platform
from scapy.all import sniff # sniff to sniff arp packets.

connection_request = []
numOfReplies = {}
timeAtRequest = {}
sent_notifications = []
required_modules = ["netifaces", "scapy", "AppKit"]

ip_addr = ""
broadcast_addr = ""

# Set maximum number of ARP reply packets. If computer receives 7 ARP reply packets then notifies user.
request_threshold = 7

request_time_limit = 60

def MacSpoofScanner():
    # determine if user has root permissions
    if os.geteuid() != 0:
	       exit("Root permisson is needed to manage network interfaces. Aborting.")
    else:
        print("Current user has permissions.")

    print("Info will be stored in a log titled \"ARP log - Mac.txt\"")

    # format log
    formatLog()

    # do scanner things

    macNotification("Spoof Notification", "Anti-spoofing script is running", "Your network is being protected")

    # Only sniff arp packets.
    sniff(filter = "arp", prn = packet_filter, store = 0)


def spoofChecker (source, mac, destination):
    if destination == broadcast_addr and mac not in numOfReplies:
            numOfReplies[mac] = 0
            timeAtRequest[mac_addr] = calendar.timegm(time.gmtime())

    if not source in connection_request and source != ip_addr:
        if mac in numOfReplies:
            numOfReplies[mac] += 1
        else:
            numOfReplies[mac] = 0
            timeAtRequest[mac_addr] = calendar.timegm(time.gmtime())

        logging.warning("Request count {}".format(mac, numOfReplies[mac]))

        # Check whether or not number of replies reach a threshold and check for whether if not the notification is already displayed
        timeDiff = calendar.timegm(time.gmtime()) - timeAtRequest[mac_addr]
        if numOfReplies[mac_addr] > request_limit and timeDiff < request_time_limit:
            # Log the attack to the log file
            logging.error("ARPSpoof Detected from MAC Address {}".format(mac))

            if mac_addr not in sent_notifications:
                # if spoof detected, then issue a notification
                macNotification("Spoof Notification", "Your network is under attack", "Detected from {}.".format(mac))

                # Add to sent_notifications list so that the notification won't be repeated.
                sent_notifications.append(mac)

                # Once spoofing detected. Tell Mac to disconnect active wifi.
                os.system("networksetup -setairportpower airport off")

    else:
        if source in connection_request:
            connection_request.remove(source)


def packet_filter (packet):
    # Retrieve necessary parameters from packet
    source = packet.sprintf("%ARP.psrc%")
    destination = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    op = packet.sprintf("%ARP.op%")
    if source == ip_addr:
        connection_request.append(destination)
    if op == 'is-at':
        return spoofChecker(source, source_mac, destination)

def checkInterface(i, interface_list):
    if not i in interface_list:
        print("Interface {} not available.".format(i))
        interface = input("Please select the interface again: {}\n".format(str(interface_list)))
        checkInterface(interface, interface_list)
    else:
        # Retrieve network addresses (IP, broadcast_addr) from the network interfaces
        addrs = netifaces.ifaddresses(i)
        try:
            ip_addr = addrs[netifaces.AF_INET][0]["addr"]
            broadcast_addr = addrs[netifaces.AF_INET][0]["broadcast"]
        except KeyError:
            exit("Cannot read address/broadcast address on interface {}".format(i))

def formatLog():
    # define logging format and log name
    FORMAT = '%(asctime)s: %(message)s'
    LOG_NAME = "ARP log - Windows.txt"

    # create log with format defined above
    logging.basicConfig(format=FORMAT, filename=LOG_NAME)

    # import available network interfaces
    available_interfaces = netifaces.interfaces()

    # Ask user for desired interface
    interface = input("Please select the interface you wish to listen to: {}\n".format(str(available_interfaces)))

    # Check if specified interface is valid. Allows user to input again if first input is incorrect.
    checkInterface(interface, available_interfaces)

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
    MacSpoofScanner()

if __name__ == '__main__':
	main()
