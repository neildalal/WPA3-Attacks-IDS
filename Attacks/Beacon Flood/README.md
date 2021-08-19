This attack can easily be launched with MDK3 tool which comes preinstalled with Kali Linux. We simply run:
```
$ sudo mdk3 wlan0 b -n FreeWifi
$ sudo mdk3 wlan0 b -f ssid_list.txt
```
The first command will broadcast an SSID named ’FreeWifi’, while the second command
reads a list of SSIDs from the file 'ssid list.txt' and broadcasts them.

The file 'beacon.pcapng' is the packet capture file of when one such attack was executed. Below image shows the result of the impact of the attack when executed.

![image](https://user-images.githubusercontent.com/44478153/130040627-3ee752ba-e67e-4a96-b225-3d802f01c432.png)
