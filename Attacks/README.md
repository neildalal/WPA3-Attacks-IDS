Except the SAE Authentication flood, Timing Side Channel and Beacon Flood attacks, all other attacks require the attacker to behave as a rogue AP, sending modified packets. For this we run hostapd on are attack node. We setup and configure hostapd-2.9 to run as
an AP with the same SSID and MAC address as our target AP. We also set it to run on
the same channel as the target AP. We get this information about the MAC address and
channel of operation of the target AP by sniffing the channel by running airodump-ng [38] on
a NIC that supports monitor mode.
