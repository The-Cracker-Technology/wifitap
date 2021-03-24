Wifitap
=======

	#########################################
	#
	# wifitap.py --- WiFi injection tool through tun/tap device
	# Cedric Blancher <sid@rstack.org>
	#
	# http://sid.rstack.org/index.php/Wifitap (french)
	# http://sid.rstack.org/index.php/Wifitap_EN (english)
	#
	#########################################

This program is a proof of concept tool allowing WiFi communications using
traffic injection.

You'll need:

	. Python >= 2.2
	. Philippe Biondi's Scapy
	. Injection ready wireless adapter

It's been tested on GNU/Linux using Atheros chipset based adapter with patched
Madwifi driver and Intersil Prism GT Full MACchipset with Prism54 driver. It
should as well work with Prism2/2.5/3 chipset hostap driver or wlan-ng driver,
Ralink rt2500/2750 chipset using rt2500 driver and Realtek RTL8180 chipset
using rtl8180-sa2400 driver.

I didn't take time to test Prism2/2.5/3 support and don't have Ralink or Realtek
based hardware for testing. By the way, I would be glad to have feedback for
Wifitap attempts with thoses chipsets.

Drivers patches are written by Christophe Devine and updated by Aircrack-ng
people. For details about drivers patch and installation, see PATCHING file.

To get wifitap work on other Unix operating systems than GNU/Linux, you have to
install pcap or dnet wrappers for Python so Scapy can work (see
http://www.secdev.org/projects/scapy/portability.html). Then, and it's the most
important part, you have to find a wireless adapter driver that supports raw
wireless traffic injection if any.

   * [Setup Guide](#setup-guide)
      * [Getting Wifitap ;)](#getting-wifitap-)
      * [Installing Dependencies](#installing-dependencies)
   * [Usage Guide](#usage-guide)
      * [Launching Wifitap](#launching-wifitap)
      * [Wifitap Command Line Arguments](#wifitap-command-line-arguments)

Setup Guide
===========

Getting Wifitap ;)
------------------

The latest Wifitap can be obtained from this Git repo.

Older versions of Wifitap are available at the following locations:

- [http://sid.rstack.org/index.php/Wifitap (french)](http://sid.rstack.org/index.php/Wifitap)
- [http://sid.rstack.org/index.php/Wifitap\_EN (english)](http://sid.rstack.org/index.php/Wifitap_EN)



Installing Dependencies
-----------------------

Python dependencies are enumerated in `pip.req`, can be installed using the pip as shown below.

	pip install -r pip.req

Wifitap's most important dependency is Scapy, which you should check out because it's totally awesome.

 - [http://www.secdev.org/projects/scapy/](http://www.secdev.org/projects/scapy/)


Usage Guide
===========

Launching Wifitap
-----------------

Before you start, make sure your wireless interface is in monitor mode. In the commands shown below, substitute "wlan0" for the name of your wireless interface.
	
	ifconfig wlan0 down
	iw dev wlan0 set monitor none
	ifconfig wlan0 up promisc

To launch Wifitap with basic options, use the following command:

	./wifitap.py -b <bssid>

This will create a wj0 interface. Next, you'll need to configure this new interface using syntax shown below. Note that you can optionally specify the MAC in the following command.

	ifconfig wj0 [hw ether <MAC>] 192.168.1.1 [mtu <MTU>]

You'll now be able to use your newly created wj0 interface as if it were normal network interface, according to your system routing table. :)


Wifitap Command Line Arguments
------------------------------

	Usage : wifitap -b <BSSID> [-o <iface>] [-i <iface> [-s <SMAC>]
			[-w <WEP key> [-k <key id>]] [-d [-v]] [-h]

	-b	Specifies BSSID in ususal 6 hex digits MAC address format:
			. 00:01:02:03:04:05

	-o	Specifies output WiFi interface for frames injection

	-i	Specifies input WiFi interface for frames sniffing

	-s	Specifies source MAC address
			. 00:01:02:03:04:05

	-w	Activates WEP encryption/decryption with specified WEP key
		Key can be given using following formats:
			. 0102030405 or 0102030405060708090a0b0c0d
			. 01:02:03:04:05 or
			  01:02:03:04:05:06:07:08:09:0a:0b:0c:0d
			. 0102-0304-05 or 0102-0304-0506-0708-090a-0b0c-0d

	-k	Specifies WEP key id, from 0 to 3

	-d	Activates debugging

	-v	Increases debugging verbosity

	-h	Help screen

	#########################################
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
