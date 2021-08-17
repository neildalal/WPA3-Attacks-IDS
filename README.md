# WPA3-Attacks-IDS

• A laptop running Kali Linux 2020.4 as our attack node
• A NIC comprising an Atheros based chipset, with support for monitor mode, packet
injection and 802.11ac protocol
• A second NIC with support for monitor mode
• An AP and a client with support for 802.11ax and WPA3-SAE Wi-Fi security

# Installing the relevant dependencies
The drivers for most popular wireless adapters come pre-compiled with Kali Linux and there
shouldn’t be a need to install them specifically.
Some of the attacks require the the wireless card to have the ability to acknowledge frames
sent to spoofed MAC addresses. Currently this acknowledgement functionality is available
only for Atheros based cards hence we need our NIC to be Atheros based. This ’ath masker’
kernel module can be enabled by cloning the git repository in [4] and then simply running
./load.sh in that folder from the terminal.

We need to install some necessary packages which can be done by running the below mentioned commands:
$ sudo apt-get install autoconf automake libtool shtool libssl-dev pkg-config
$ apt install pkg-config
$ apt install libnl-3-dev
$ apt install libssl-dev
$ apt install libnl-genl-3-dev

# Several useful commands
To disable Wi-Fi in your network manager run
$ sudo airmon-ng check kill
$ sudo service network-manager stop
$ sudo rfkill unblock wifi
To check the list of connected NICs run
$ sudo airmon-ng
To put a particular NIC, say ’wlan0’, in monitor mode run
$ sudo ifconfig wlan0 down
$ sudo iw wlan0 set type monitor
$ sudo ifconfig wlan0 up
We can sniff the network and start a capture session in order to get important information
such as the mac address of the access points(APs), the clients connected to it, the SSID’s
present in the network, the channels on which the APs are operating, the supported authentication mechanism of the APs, etc. To do this put the NIC, say wlan0, in monitor mode
and then run:
$ airodump-ng wlan0

# Installing and setting up Hostapd v2.9
Download and extract Hostapd v2.9 from https://w1.fi/releases/hostapd-2.9.tar.gz
Next compile it by:
$ cd hostapd-2.9/hostapd
$ cp defconfig .config
$ make -j 2
We can set our configuration for hostapd in a file. The below mentioned file, named
’wpa3.conf’ is an example of one such configuration.

We can then finally run hostapd as follows,
#First disable Wi-Fi in the network manager. Then put the Alfa NIC in monitor mode.
#Refer Section 4.3 for how to do this. Then simply run:
$ ./hostapd wpa3.conf -dd -K
