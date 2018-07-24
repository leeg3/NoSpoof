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

# store any connection requests
connection_request = []
# store the number of replies per address
numOfReplies = {}
# determine if a notification for an IP has been sent already
sent_notifications = []
# list required modules in order for script to run
required_modules = ["netifaces", "win10toast", "scapy"]

# strings to store assigned ip address and broadcast IP address
ip_addr = ""
broadcast_addr = ""

# Number of ARP replies received from a specific mac address before marking as ARP spoof
request_limit = 7


# function to create and format the log
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

    # Retrieve internet addresses (IP, broadcast) from the network interfaces
    addrs = netifaces.ifaddresses(networkInterfaces[selection])
    try:
        ip_addr = addrs[netifaces.AF_INET][0]["addr"]
        broadcast_addr = addrs[netifaces.AF_INET][0]["broadcast"]
        print("Your IP address: ", ip_addr)
        print("Your broadcast IP address: ", broadcast_addr)
    except KeyError:
        exit("Cannot read address/broadcast address on interface {}".format(networkInterfaces[int(selection)]))


# filters the packets sent to it
def packet_filter (packet):
    # Retrieve info from packet
    source = packet.sprintf("%ARP.psrc%")
    destination = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    op = packet.sprintf("%ARP.op%")

    # if packet is from this computer, then save its destination into connection_request
    if source == ip_addr:
        connection_request.append(destination)

    # if the operation is in "is-at" check for spoof
    if op == 'is-at':
        return check_spoof (source, source_mac, destination)


# Function checks if a specific ARP reply is part of an ARP spoof attack or not
def check_spoof (source, mac, destination):
    # if the destination of the received packet is the same as the broadcast address, add into numOfReplies if not added already
    if destination == broadcast_addr:
        if not mac in numOfReplies:
            numOfReplies[mac] = 0

    # if the source IP is found in the connection request and it is not he local_ip, then increment otherwise reset to 0
    if not source in connection_request and source != local_ip:
        if not mac in numOfReplies:
            numOfReplies[mac] = 0
        else:
            numOfReplies[mac] += 1

        # add entry into log about an ARPSpoofing attempt
        logging.warning("ARPSpoofing replies detected from {}. Request count #{}".format(mac, numOfReplies[mac]))

        # if the number of replies from a single source is more than the limit, and a notification has not been sent, add an entry into the log and send notification, then add to sent_notifications list
        if (numOfReplies[mac] > request_limit) and (not mac in notification_issued):
            logging.error("ARP Spoofing Detected from MAC Address {}".format(mac))
            sendNotification(mac)
            sent_notifications.append(mac)
    else:
        if source in connection_request:
            connection_request.remove(source)


# display a notification to the user about an ARPSpoofing attempt
def sendNotification(mac):
    toaster = ToastNotifier()
    toaster.show_toast("ARPSpoofing Detected", "ARPSpoofing attack detected from {}.".format(mac))


def main():
    # retrieve system OS
    system_os = platform.system()

    # Determine system OS and execute appropriate function
    if system_os == 'Windows': # Windows
        # retrieve installed python modules
        installed_modules = subprocess.check_output("pip freeze")

        # check for required modules, exit if any one of them are missing
        for elem in required_modules:
            if elem not in str(installed_modules):
                exit("Missing python modules. Please check to ensure that the required modules are installed.")

        # determine if the user has Admin permission. If not then exit
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            exit("Admin permission is needed to manage network interfaces. Please use an admin account and Admin Powershell to execute.")
        else:
            print("Current user has necessary permisisons.")

        print("Info will be stored in a log titled \"ARP log - Windows.txt\"")

        # format log
        formatLog()
        print("ARP Spoofing Detection Started. Any output is redirected to log file.")

        # use sniff tool to sniff the packets and send them to the packet_filter
        sniff(filter = "arp", prn = packet_filter, store = 0)
    else:
        print("Operating System not supported. Please ensure that you have the correct script for your operating system.")


if __name__ == '__main__':
	main()
