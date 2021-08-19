We modify the source code of hostapd-2.9 in such a way that the attacker’s access point sends a deauthentication packet to the client right after the
client completes authentication and sends an association request packet to the legitimate AP. For this we modify
the code located in /hostapd-2.9/src/ap/ieee802_11.c. The modified ieee802_11.c file is already provided.
Next we recompile and run hostapd-2.9. While the attack
is running, we found that every single time a client tries to initiate an authentication, it
receives the rejection message from the attacker’s AP first and aborts the handshake, thus
preventing new clients from joining.
We can keep the rate of beacon as low as possible and also set the SSID to be hidden. This
will help keep the attack as passive as possible and difficult for an IDS to detect it. This
can be achieved by setting ’ignore broadcast ssid=1’ and ’beacon int=9999’ in the .conf file
of hostapd. We have already done this in the 'wpa3.conf' file.

To launch the attack, first download hostapd, then replace the ieee802_11.c file locted at /hostapd-2.9/src/ap/ieee802_11.c with the one we provide. Next recompile hostapd using the commands mentioned in the `prerequisite` section of the readme.md file of the root folder of this repository.
Then run hostapd with our wpa3.conf configuration file as ”sudo ./hostapd wpa3.conf -dd -K”.

We observe that when the attack is in operation, no new clients are able to join the network. Our clients would either get stuck on ”Obtaining IP Address” or get the error - ”Check Password and try Again”. As soon as the attack is stopped, all clients are able to successfully connect to the network.

The file deauth.pcapng is captured when the attack is ran against our target AP and we try to connect a client to the network.
Notice the sequence of packets from 621 to 642. We can see that the attacker's access point (with the same MAC address as the legitimate AP)
sends a deauthentication packet (No. 635) to the client which eventually leads to a mismatch
of states between the client and legitimate AP and abortion of the handshake. 
This sequence of packets captured during the attack matches with the packet sequence we expect
theoretically.

