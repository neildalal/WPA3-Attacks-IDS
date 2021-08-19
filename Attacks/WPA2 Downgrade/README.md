

We want the attacker to behave as a rogue AP, sending modified beacons.
For this we run hostapd on are attack node. We setup and configure hostapd-2.9 to run as
an AP with the same SSID and MAC address as our target AP. We also set it to run on
the same channel as the target AP. We get this information about the MAC address and
channel of operation of the target AP by sniffing the channel by running airodump-ng [38] on
a NIC that supports monitor mode. We increase the rate of beacons sent by our rogue AP
by setting the beacon interval in the configuration file to 16. This means our rogue AP will
send a beacon every 16ms as opposed to our legitimate AP doing so every 100ms. Lastly, we
set the wpa key mgmt to WPA2 security. Table 2 shows the ’wpa2.conf’ file which we use to
set everything as required. Then we simply launch the attack by running ”sudo ./hostapd
wpa2.conf -dd -K”. We observe that when the attack is in operation, no new clients are able
to join the network. Our clients would either get stuck on ”Obtaining IP Address” or get
the error - ”Check Password and try Again”. As soon as the attack is stopped, all clients
are able to successfully connect to the network. Figure 9 shows the packets captured during
the attack which matches with the packet sequence we expect theoretically.