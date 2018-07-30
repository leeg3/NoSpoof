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
try an add a time limit for arp requests, testing shows that aircrack-ng? tries to do the spoof in like 30 seconds
TEST
"""

import os, sys, time, calendar, logging, ctypes, platform, subprocess, netifaces
from win10toast import ToastNotifier
from scapy.all import sniff

# store any connection requests
connection_request = []
# store the number of replies per address
numOfReplies = {}
# store time at which first ARP request occured
timeAtRequest = {}
# store sent notifications to prevent repeat notifications for the same mac address
sent_notifications = []
# list required modules in order for script to run
required_modules = ["netifaces", "win10toast", "scapy"]

# strings to store assigned ip address and broadcast IP address
ip_addr = ""
broadcast_addr = ""

# Number of ARP replies received from a specific mac address before marking as ARP spoof
request_limit = 7

# number of seconds an arpspoof is executed in. This is reflected in testing
request_time_limit = 60


# function to create and format the log
def formatLog():
    # define logging format and log name
    FORMAT = '%(asctime)s: %(message)s'
    LOG_NAME = "ARP log - Windows.txt"

    # create log with format defined above
    logging.basicConfig(format=FORMAT, filename=LOG_NAME)

    # import connected network interfaces into a list
    networkInterfaces = netifaces.interfaces()

    # output all network interfaces and their corresponding index
    num = 0
    print("Connected Network Interfaces:")
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
        exit("Cannot read address/broadcast address on interface {}".format(networkInterfaces[selection]))


# filters the packets sent to it
def sortPackets(packet):
    # Retrieve source, destination, hardware source and operation from packet
    packet_src = packet.sprintf("%ARP.psrc%")   # packet source
    packet_dest = packet.sprintf("%ARP.pdst%")  # packet destination
    source_mac = packet.sprintf("%ARP.hwsrc%")  # hardware source
    packet_op = packet.sprintf("%ARP.op%")      # packet operation

    # if packet is from this computer, then save its destination into connection_request
    if packet_src == ip_addr:
        connection_request.append(packet_dest)

    # if the operation is in "is-at" check for spoof
    if packet_op == 'is-at':
        return checkARPspoof(packet_src, source_mac, packet_dest)


# checks if a packet is part of an ARP spoof attack
def checkARPspoof(source, mac_addr, destination):
    # if the mac address is not in the list and destination of the received packet is the same as the broadcast address then add into list
    if mac_addr not in numOfReplies and broadcast_addr == destination:
        numOfReplies[mac_addr] = 0
        timeAtRequest[mac_addr] = calendar.timegm(time.gmtime())

    # if the source IP is found in the connection request and it is not the ip_addr, then increment otherwise reset to 0 and reset time
    if source not in connection_request and source != ip_addr:
        if mac_addr in numOfReplies:
            numOfReplies[mac_addr] += 1
        else:
            numOfReplies[mac_addr] = 0
            timeAtRequest[mac_addr] = calendar.timegm(time.gmtime())

        # add a warning entry into log about an ARPSpoofing attempt
        logging.warning("ARP reply from {}, Request count #{}".format(mac_addr, numOfReplies[mac_addr]))

        # If the number of replies from a single source is more than the limit, add an entry into the log. Send notification if one has not been sent already, then add to sent_notifications list and disableWifi on machine
        timeDiff = calendar.timegm(time.gmtime()) - timeAtRequest[mac_addr]
        if numOfReplies[mac_addr] > request_limit and timeDiff < request_time_limit:
            logging.error("Detected ARPSpoofing from {}".format(mac_addr))
            if mac_addr not in sent_notifications:
                sendNotification(mac_addr)
                sent_notifications.append(mac_addr)
                disableWifi()
    else:
        if source in connection_request:
            connection_request.remove(source)


# display a notification to the user about an ARPSpoofing attack
def sendNotification(mac):
    toaster = ToastNotifier()
    toaster.show_toast("Warning: ARPSpoof Detected", "Attack detected from {}.".format(mac), duration=10)


# disable wifi on system
def disableWifi():
    subprocess.call("powershell Disable-NetAdapter -Name \"Wi-Fi\" -Confirm:$false")
    print("ARPSpoof detected, disabled Wi-Fi")


def main():
    # retrieve system OS
    system_os = platform.system()

    # Determine if system OS is compatible with this script
    if system_os == 'Windows': # Windows
        # retrieve installed python modules
        installed_modules = subprocess.check_output("pip freeze")

        # check for required modules, exit if any one of them are missing
        for elem in required_modules:
            if elem not in str(installed_modules):
                exit("Missing python modules. Please check to ensure that the required modules are installed.")

        # determine if the user has Admin permission. If not then exit
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            exit("Admin permission is needed to manage network interfaces. Please use an admin account and Admin Command Prompt/Powershell to execute.")
        else:
            print("Current user has necessary permisisons.")

        print("Output will be stored in a log named \"ARP log - Windows.txt\"")

        # format log
        formatLog()

        print("Starting ARPSpoofing detector. If an ARPSpoof attack is detected, you will be notified.")

        # use sniff to sniff for ARP packets and send them to sortPackets to be filtered. Do not store any packets
        # change from arp to ether proto arp here. should work
        sniff(filter = "ether proto arp", prn = sortPackets, store = 0)
    else:
        print("Operating System not supported. Please ensure that you have the correct script for your operating system.")


if __name__ == '__main__':
	main()
