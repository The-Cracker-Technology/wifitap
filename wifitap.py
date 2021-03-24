#! /usr/bin/env python

########################################
#
# wifitap.py --- WiFi injection tool through tun/tap device
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
import struct
import logging
import argparse
import utils

from socket import *
from fcntl  import ioctl
from select import select

logging.getLogger("scapy").setLevel(1)
#from scapy  import Raw,Ether,PrismHeader,Dot11,Dot11WEP,LLC,SNAP,sendp,conf
from scapy.all import Raw,Ether,PrismHeader,Dot11,Dot11WEP,LLC,SNAP,sendp,conf,RadioTap

TUNSETIFF = 0x400454ca
IFF_TAP   = 0x0002
TUNMODE   = IFF_TAP

def setup():

    global conf

    parser = argparse.ArgumentParser()
    parser.add_argument('-b',
                    dest='bssid',
                    type=utils.sanitize_bssid,
                    required=True,
                    help='Specify BSSID for injection')

    parser.add_argument('-o',
                    dest='out_iface',
                    default='wlan0',
                    type=str,
                    help='Specify iface for injection (default: wlan0)')

    parser.add_argument('-i',
                    dest='in_iface',
                    default='wlan0',
                    type=str,
                    help='Specify iface for listening (default: wlan0)')

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
                    dest='verb',
                    action='store_true',
                    help='Use verbose debugging.')

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

    print "in_iface:   %s" % options.in_iface
    print "out_iface:  %s" % options.out_iface
    print "bssid:      %s" % options.bssid
    if options.smac is not None:
    
        print "smac:       %s" % options.smac
    
    if options.wepkey is not None:

        print "WEP key:    %s (%dbits)" % (options.wepkey, len(options.wepkey)*4)

    print 'DEBUG mode:', options.debug

if __name__ == '__main__':

    options = setup()
    print_options(options)
    
    # Here we put a BPF filter so only 802.11 Data/to-DS frames are captured
    s = conf.L2listen(iface = options.in_iface,
                    filter = "link[0]&0xc == 8 and link[1]&0xf == 1")
    #s = conf.L2listen(iface = options.in_iface)
    
    # Open /dev/net/tun in TAP (ether) mode
    f = os.open("/dev/net/tun", os.O_RDWR)
    ifs = ioctl(f, TUNSETIFF, struct.pack("16sH", "wj%d", TUNMODE))
    ifname = ifs[:16].strip("\x00")
    print "Interface %s created. Configure it and use it" % ifname
    
    # Speed optimization si Scapy does not have to parse payloads
    Ether.payload_guess=[]
    SNAP.payload_guess=[]
    
    try:
    
        while True:
    
            r = select([f,s],[],[])[0]
        
            # frame from /dev/net/tun
            if f in r:
            
                # tuntap frame max. size is 1522 (ethernet, see RFC3580) + 4
                buf = os.read(f,1526)
                eth_rcvd_frame=Ether(buf[4:])
                
                if options.debug:
                    os.write(1,"Received from %s\n" % ifname)
                    if options.verb:
                        os.write(1,"%s\n" % eth_rcvd_frame.summary())
                
                # Prepare Dot11 frame for injection
                dot11_sent_frame = RadioTap()/Dot11(
                type = "Data",
                FCfield = "from-DS",
                addr1 = eth_rcvd_frame.getlayer(Ether).dst,
                addr2 = options.bssid)
                # It doesn't seem possible to set tuntap interface MAC address
                # when we create it, so we set source MAC here
                if options.smac is None:
                    dot11_sent_frame.addr3 = eth_rcvd_frame.getlayer(Ether).src
                else:
                    dot11_sent_frame.addr3 = options.smac
                if options.wepkey is not None:
                    dot11_sent_frame.FCfield |= 0x40
                    dot11_sent_frame /= Dot11WEP(iv = "111", keyid = options.keyid)
    
                dot11_sent_frame /= LLC(ctrl = 3)/SNAP(code=eth_rcvd_frame.getlayer(Ether).type)/eth_rcvd_frame.getlayer(Ether).payload
                
                if options.debug:
                    os.write(1,"Sending from-DS to %s\n" % options.out_iface)
                    if options.verb:
                        os.write(1,"%s\n" % dot11_sent_frame.summary())
                
                # Frame injection :
                sendp(dot11_sent_frame,verbose=0) # Send from-DS frame
            
            # Frame from WiFi network
            if s in r:
            
                # 802.11 maximum frame size is 2346 bytes (cf. RFC3580)
                # However, WiFi interfaces are always MTUed to 1500
                dot11_rcvd_frame = s.recv(2346)
            
                # WEP handling is automagicly done by Scapy if conf.wepkey is set
                # Nothing to do to decrypt (although not yet tested)
                # WEP frames have Dot11WEP layer, others don't
            
                if options.debug:
                    if dot11_rcvd_frame.haslayer(Dot11WEP): # WEP frame
                        os.write(1,"Received WEP from %s\n" % options.in_iface)
                    else: # Cleartext frame
                        os.write(1,"Received from %s\n" % options.in_iface)
                    if options.verb:
                        os.write(1,"%s\n" % dot11_rcvd_frame.summary())
            
                # if dot11_frame.getlayer(Dot11).FCfield & 1: # Frame is to-DS
                # For now, we only take care of to-DS frames...
                if dot11_rcvd_frame.getlayer(Dot11).addr1 != options.bssid:
                    if options.verb:
                        os.write(1,"Frame not to/from BSSID\n")
                    continue
            
                # One day, we'll try to take care of AP to DS trafic (cf. TODO)
                #    else: # Frame is from-DS
                #        if dot11_frame.getlayer(Dot11).addr2 != options.bssid:
                #            continue
                #   eth_frame = Ether(dst=dot11_frame.getlayer(Dot11).addr1,
                #           src=dot11_frame.getlayer(Dot11).addr3)
                
                if dot11_rcvd_frame.haslayer(SNAP):
                    eth_sent_frame = Ether(dst=dot11_rcvd_frame.getlayer(Dot11).addr3,
                                        src=dot11_rcvd_frame.getlayer(Dot11).addr2,
                                        type=dot11_rcvd_frame.getlayer(SNAP).code)
                    eth_sent_frame.payload = dot11_rcvd_frame.getlayer(SNAP).payload
            
                if options.debug:
                    os.write(1, "Sending to %s\n" % ifname)
                    if options.verb:
                        os.write(1, "%s\n" % eth_sent_frame.summary())
            
                # Add Tun/Tap header to frame, convert to string and send
                buf = "\x00\x00" + struct.pack("!H",eth_sent_frame.type) + str(eth_sent_frame)
                os.write(f, buf)
    
    # Program killed
    except KeyboardInterrupt:
        print "\nStopped by user."
    
    s.close()
    os.close(f)
    
    sys.exit()
