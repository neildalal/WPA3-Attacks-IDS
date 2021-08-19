We want the attacker to behave as a rogue AP, sending modified beacons. For this we run hostapd on are attack node. We setup and configure hostapd-2.9 to run as an AP with the same SSID and MAC address as our target AP. We also set it to run on the same channel as the target AP. We increase the rate of beacons sent by our rogue AP by setting the beacon interval in the configuration file to 16. This means our rogue AP will send a beacon every 16ms as opposed to our legitimate AP doing so every 100ms. Lastly, we set the wpa key mgmt to WPA2 security. The file ’wpa2.conf’ is used to set everything as required.

So to launch the attack, simply download and compile hostapd, then run hostapd with this configuration file as ”sudo ./hostapd wpa2.conf -dd -K”.

We observe that when the attack is in operation, no new clients are able to join the network. Our clients would either get stuck on ”Obtaining IP Address” or get the error - ”Check Password and try Again”. As soon as the attack is stopped, all clients are able to successfully connect to the network.

The file wpa3_only.pcapng is captured when the attack is ran with our target AP security set to WPA3 only. The file wpa3_transition_mode.pcapng is captured when the attack is ran with our target AP set in transition mode (supporting both WPA3 and WPA2)

In the file wpa3_transition_mode.pcapng, observe the sequence of packets from No. 290 to 297. We see that the client aborts the handshake after receiving message 3 of the EAPOL handshake when it realizes that there is a mismatch in the RSNE information which it possesses vs what our AP possesses. The Beacons of length 124 with beacon interval (BI) = 16 are from the attacker node and beacons of length 351 with BI = 100 are from our own AP.
