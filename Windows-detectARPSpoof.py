#!/usr/bin/env python

"""
Authors: Greg Lee, An Nguyen
Date: 7/17/18
Description: This script is designed to look for ARPSpoofing which is a key step in order to execute a Man in the Middle Attack. If an attack is detected, then a notification is sent to the user.

execute instructions:
sudo python3 detectARPSpoof.py

"""

import os, time, netifaces, sys, logging, ctypes, platform
from win10toast import ToastNotifier
from scapy.all import sniff

ipaddr = ""
broadcast = ""
requests = []
replies_count = {}
notification_issued = []


def WindowsSpoofScanner():
    # determine if the user has Admin permission. If not then exit
    if ctypes.windll.shell32.IsUserAnAdmin() != 0:
        exit("Admin permission is needed to manage network interfaces. Aborting.")
    else:
        print("Current user has necessary permisisons.")

    # format log
    formatLog()

    print("ARP Spoofing Detection Started. Any output is redirected to log file.")

    # sniff is used to sniff the packets and send them to the packet_filter
    sniff(filter = "arp", prn = packet_filter, store = 0)


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
            #issue_os_notification("ARP Spoofing Detected", "The current network is being attacked.", "ARP Spoofing Attack Detected from {}.".format(mac))
            sendNotification(mac)
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

    # send packets to be checked for spoofing
    if source == ipaddr:
        requests.append(destination)
    if op == 'is-at':
        return check_spoof (source, source_mac, destination)



def sendNotification():
    toaster = ToastNotifier()
    toaster.show_toast("ARPSpoofing Detected", "ARPSpoofing attack detected from {}.".format(mac))


def formatLog():
    # define logging format
    logging.basicConfig(format='%(asctime)s: %(message)s', filename="Windows ARP log.txt")

    # import connected network interfaces into a list
    networkInterfaces = netifaces.interfaces()

    # output all network interfaces
    num = 0
    print("Available network interfaces")
    for elem in networkInterfaces:
        print("[{}]: {}".format(num, networkInterfaces[num]))
        num+=1

    # decrement num by 1
    num-=1

    # prompt for user input
    selection = input("Please select an interface to use: ")

    # check input and make sure they selected a valid input
    if num > len(networkInterfaces):
        exit("Incorrect value inputted. Exiting")

    # Retrieve network addresses (IP, broadcast) from the network interfaces
    addrs = netifaces.ifaddresses(networkInterfaces[num])
    try:
        ipaddr = addrs[netifaces.AF_INET][0]["addr"]
        broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
    except KeyError:
        exit("Cannot read address/broadcast address on interface {}".format(networkInterfaces[num]))

    logging.info("ARPSpoofing Detection started on {}".format(ipaddr))

def main():
    # retrieve system OS
    system_os = platform.system()

    # Determine system OS and execute appropriate function
    if system_os == 'Windows': # Windows
        print("Info will be stored in a log titled \"Windows ARP log.txt\"")
        WindowsSpoofScanner()
    else:
        print("Operating System not supported")


if __name__ == '__main__':
	main()
