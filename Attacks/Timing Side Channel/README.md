This attack is descirbed in [[1]](#1) and the author also provides a tool along with steps for performing this attack in https://github.com/vanhoefm/dragondrain-and-time. Please refer to the link for the same.

An AP is vulnerable to this attack only if it uses weaker groups 22-24 (MODP groups) and 27-30 (Brainpool groups) during SAE authentication. Our AP didn’t support these groups
and hence was not vulnerable to this attack. We sent authentication requests using different groups and our AP rejected authentication when any of these weaker groups were used.
The files `timing_g19.pacpng` and `timing_g27.pacpng` are packet captures of when we executed this attack using cryptographic groups 19 and 27 respectively.
When group 19 is used, the AP replies back with successful authentication but the timing attack is not possible using this group.
When group 27 is used, we can see that the AP rejects authentication with - 'Status code: Authentication is rejected because the offered finite cyclic group is not supported (0x004d)'. For example, see status code of packet no. 64 in timing_g27.pcapng. Simlarly it rejected authentication when any of the groups 22-24 and 27-30 were used.

## References
<a id="1">[1]</a> 
Mathy Vanhoef and Eyal Ronen. 
Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd.
IEEE Symposium on Security & Privacy (SP) (2020).
