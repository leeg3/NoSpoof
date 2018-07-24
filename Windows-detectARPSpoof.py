#!/usr/bin/env python

"""
Authors: Greg Lee, An Nguyen
Date: 7/17/18
Description: This script is designed to analyze internet traffic for ARPSpoofing which is a key step in order to execute a Man in the Middle Attack. If an attack is detected, then a notification is sent to the user.

Requirements:
1. python3
2. winpcap
3. netifaces, win10toast, scapy python modules
4. admin account
5. admin powershell

execute instructions:
(in admin powershell with admin account)
python3 detectARPSpoof.py

Notes:
How do i make windows network interfaces more readable?
"""

import os, time, netifaces, sys, logging, ctypes, platform, subprocess
from win10toast import ToastNotifier
from scapy.all import sniff

requests = []
replies_count = {}
sent_notifications = []
required_modules = ["netifaces", "win10toast", "scapy"]

# strings to store assigned ip address and broadcast IP address
ip_addr = ""
broadcast_addr = ""

# Number of ARP replies received from a specific mac address before marking as ARP spoof
request_limit = 7


def packet_filter (packet):
    # Retrieve info from packet
    source = packet.sprintf("%ARP.psrc%")
    destination = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    op = packet.sprintf("%ARP.op%")

    # if packet is from this computer, then save its destination into requests
    if source == ip_addr:
        requests.append(destination)
    if op == 'is-at':
        return check_spoof (source, source_mac, destination)


def check_spoof (source, mac, destination):
    # Function checks if a specific ARP reply is part of an ARP spoof attack or not
    if destination == broadcast_addr:
        if not mac in replies_count:
            replies_count[mac] = 0

    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1

        # Logs ARP Reply
        logging.warning("ARPSpoofing replies detected from {}. Request count #{}".format(mac, replies_count[mac]))

        if (replies_count[mac] > request_limit) and (not mac in notification_issued):
            # Check number of replies reaches threshold or not, and whether or not we have sent a notification for this MAC addr
            logging.error("ARP Spoofing Detected from MAC Address {}".format(mac)) # Logs the attack in the log file
            # Issue OS Notification
            sendNotification(mac)
            # Add to sent list to prevent repeated notifications.
            sent_notifications.append(mac)
    else:
        if source in requests:
            requests.remove(source)


def sendNotification():
    toaster = ToastNotifier()
    toaster.show_toast("ARPSpoofing Detected", "ARPSpoofing attack detected from {}.".format(mac))


def formatLog():
    # define logging format
    logging.basicConfig(format='%(asctime)s: %(message)s', filename="ARP log - Windows.txt")

    # import connected network interfaces into a list
    networkInterfaces = netifaces.interfaces()

    # output all network interfaces and their corresponding index
    num = 0
    print("Available network interfaces")
    for elem in networkInterfaces:
        print("[{}]: {}".format(num, networkInterfaces[num]))
        num+=1

    # prompt for user input
    selection = int(input("Please select an interface to use: "))

    # check input and make sure they selected a valid input
    if selection > len(networkInterfaces) or selection < 0:
        exit("Incorrect value inputted. Exiting")

    # Retrieve network addresses (IP, broadcast) from the network interfaces
    addrs = netifaces.ifaddresses(networkInterfaces[selection])
    try:
        ip_addr = addrs[netifaces.AF_INET][0]["addr"]
        broadcast_addr = addrs[netifaces.AF_INET][0]["broadcast"]
        print("Your IP address: ", ip_addr)
        print("Your broadcast IP address: ", broadcast_addr)
    except KeyError:
        exit("Cannot read address/broadcast address on interface {}".format(networkInterfaces[int(selection)]))


def main():
    system_os = platform.system() # retrieve system OS

    # Determine system OS and execute appropriate function
    if system_os == 'Windows': # Windows
        # retrieve installed python modules
        installed_modules = subprocess.check_output("pip freeze")

        # check for required modules, exit if any one of them are missing
        for elem in required_modules:
            if elem not in str(installed_modules):
                exit("Missing python modules. Please check to ensure that the required modules are installed.")

        print("Info will be stored in a log titled \"Windows ARP log.txt\"")

        # determine if the user has Admin permission. If not then exit
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            exit("Admin permission is needed to manage network interfaces. Aborting.")
        else:
            print("Current user has necessary permisisons.")

        formatLog() # format log
        print("ARP Spoofing Detection Started. Any output is redirected to log file.")

        # use sniff tool to sniff the packets and send them to the packet_filter
        sniff(filter = "arp", prn = packet_filter, store = 0)
    else:
        print("Operating System not supported. Please ensure that you have the correct script for your operating system.")


if __name__ == '__main__':
	main()
