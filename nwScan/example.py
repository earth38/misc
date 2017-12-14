#!/usr/bin/env python
# -*- coding: latin-1 -*-
import scan_candidate
import sys
import os
from pprint import pprint
import nmap                         # import nmap.py module
try:
    nm = nmap.PortScanner()         # instantiate nmap.PortScanner object
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(1)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(1)

scanPort="22,3389,25,22,139,445,80" # define scnaport
f = open('ipList')                  # read ip address
hosts = f.readlines() 
f.close()

input =  scan_candidate("192.168.186.39","25")
#input._addr = "192.168.186.39"

for host in hosts:
    host = host.strip("\n")
    nm.scan(host, scanPort)      # scan host
    #nm.scan(host, scanPort, '-sA')      # example
    
    #check if scan suceeds
    try:
        nm[host]
    except:
        print(host + ': scan failed')
        print()
        print()
        continue

    print('----------------------------------------------------')
    print('Host : {0} '.format(host))
    #print('Host : {0} '.format(host))
    print('State : {0}'.format(nm[host].state()))

    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : {0}'.format(proto))

        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            print('port : {0}\tstate : {1}'.format(port, nm[host][proto][port]))

    print()
    print()    

# Data structure looks like :
#
#      {'addresses': {'ipv4': '192.168.186.39'},
#       'hostnames': [],
#       'osmatch': [{'accuracy': '98',
#                    'line': '36241',
#                    'name': 'Juniper SA4000 SSL VPN gateway (IVE OS 7.0)',
#                    'osclass': [{'accuracy': '98',
#                                 'cpe': ['cpe:/h:juniper:sa4000',
#                                         'cpe:/o:juniper:ive_os:7'],
#                                 'osfamily': 'IVE OS',
#                                 'osgen': '7.X',
#                                 'type': 'firewall',
#                                 'vendor': 'Juniper'}]},
#                   {'accuracy': '91',
#                    'line': '17374',
#                    'name': 'Citrix Access Gateway VPN gateway',
#                    'osclass': [{'accuracy': '91',
#                                 'cpe': [],
#                                 'osfamily': 'embedded',
#                                 'osgen': None,
#                                 'type': 'proxy server',
#                                 'vendor': 'Citrix'}]}],
#       'portused': [{'portid': '443', 'proto': 'tcp', 'state': 'open'},
#                    {'portid': '113', 'proto': 'tcp', 'state': 'closed'}],
#       'status': {'reason': 'syn-ack', 'state': 'up'},
#       'tcp': {113: {'conf': '3',
#                     'cpe': '',
#                     'extrainfo': '',
#                     'name': 'ident',
#                     'product': '',
#                     'reason': 'conn-refused',
#                     'state': 'closed',
#                     'version': ''},
#               443: {'conf': '10',
#                     'cpe': '',
#                     'extrainfo': '',
#                     'name': 'http',
#                     'product': 'Juniper SA2000 or SA4000 VPN gateway http config',
#                     'reason': 'syn-ack',
#                     'state': 'open',
#                     'version': ''}},
#       'vendor': {}}




'''
nm.command_line()                   # get command line used for the scan : nmap -oX - -p 22-443 192.168.186.39
nm.scaninfo()                       # get nmap scan informations {'tcp': {'services': '22-443', 'method': 'connect'}}
nm.all_hosts()                      # get all hosts that were scanned
nm['192.168.186.39'].hostname()          # get one hostname for host 192.168.186.39, usualy the user record
nm['192.168.186.39'].hostnames()         # get list of hostnames for host 192.168.186.39 as a list of dict [{'name':'hostname1', 'type':'PTR'}, {'name':'hostname2', 'type':'user'}]
nm['192.168.186.39'].state()             # get state of host 192.168.186.39 (up|down|unknown|skipped) 
nm['192.168.186.39'].all_protocols()     # get all scanned protocols ['tcp', 'udp'] in (ip|tcp|udp|sctp)
if ('tcp' in nm['192.168.186.39']):
    list(nm['192.168.186.39']['tcp'].keys()) # get all ports for tcp protocol

nm['192.168.186.39'].all_tcp()           # get all ports for tcp protocol (sorted version)
nm['192.168.186.39'].all_udp()           # get all ports for udp protocol (sorted version)
nm['192.168.186.39'].all_ip()            # get all ports for ip protocol (sorted version)
nm['192.168.186.39'].all_sctp()          # get all ports for sctp protocol (sorted version)
if nm['192.168.186.39'].has_tcp(22):     # is there any information for port 22/tcp on host 192.168.186.39
    nm['192.168.186.39']['tcp'][22]          # get infos about port 22 in tcp on host 192.168.186.39
    nm['192.168.186.39'].tcp(22)             # get infos about port 22 in tcp on host 192.168.186.39
    nm['192.168.186.39']['tcp'][22]['state'] # get state of port 22/tcp on host 192.168.186.39 (open
'''

'''
# a more usefull example :
for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : {0} ({1})'.format(host, nm[host].hostname()))
    print('State : {0}'.format(nm[host].state()))

    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : {0}'.format(proto))

        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            print('port : {0}\tstate : {1}'.format(port, nm[host][proto][port]))


#print('----------------------------------------------------')
# print result as CSV
#print(nm.csv())
'''

'''
print('----------------------------------------------------')
# If you want to do a pingsweep on network 192.168.1.0/24:
nm.scan(hosts='192.168.0.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    print('{0}:{1}'.format(host, status))




print('----------------------------------------------------')
# Asynchronous usage of PortScannerAsync


nma = nmap.PortScannerAsync()

def callback_result(host, scan_result):
    print('------------------')
    print(host, scan_result)

nma.scan(hosts='192.168.0.0/30', arguments='-sP', callback=callback_result)


while nma.still_scanning():
    print("Waiting ...")
    nma.wait(2)   # you can do whatever you want but I choose to wait after the end of the scan

if (os.getuid() == 0):
    print('----------------------------------------------------')
    # Os detection (need root privileges)
    nm.scan("192.168.186.39", arguments="-O")
    if 'osmatch' in nm['192.168.186.39']:
        for osmatch in nm['192.168.186.39']['osmatch']:
            print('OsMatch.name : {0}'.format(osmatch['name']))
            print('OsMatch.accuracy : {0}'.format(osmatch['accuracy']))
            print('OsMatch.line : {0}'.format(osmatch['line']))
            print('')

            if 'osclass' in osmatch:
                for osclass in osmatch['osclass']:
                    print('OsClass.type : {0}'.format(osclass['type']))
                    print('OsClass.vendor : {0}'.format(osclass['vendor']))
                    print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
                    print('OsClass.osgen : {0}'.format(osclass['osgen']))
                    print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
                    print('')


    if 'fingerprint' in nm['192.168.186.39']:
        print('Fingerprint : {0}'.format(nm['192.168.186.39']['fingerprint']))


    # Vendor list for MAC address
    print('scanning localnet')
    nm.scan('192.168.0.0/24', arguments='-O')
    for h in nm.all_hosts():
        print(h)
        if 'mac' in nm[h]['addresses']:
            print(nm[h]['addresses'], nm[h]['vendor'])


print('----------------------------------------------------')
# Read output captured to a file
# Example : nmap -oX - -p 22-443 -sV 192.168.186.39 > nmap_output.xml

with open("./nmap_output.xml", "r") as fd:
    content = fd.read()
    nm.analyse_nmap_xml_scan(content)
    print(nm.csv())



print('----------------------------------------------------')
# Progressive scan with generator
nm = nmap.PortScannerYield()
for progressive_result in nm.scan('192.168.186.39/24', '22-25'):
    print(progressive_result)
'''
