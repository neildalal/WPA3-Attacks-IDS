Our IDS code IDS_WPA3.py takes 3 inputs - the packet capture file, the BSSID (MAC Address) of our target AP and the SSID set for our target AP. These are set in the code at line 47, line 7 and line 8 respectively.
After changing these appropriate fields, simply run the python code in terminal as
```
python IDS_wPA3.py
```

Note: To be able to run this python file, some packages may needed to be installed. For example, `tshark` is needed to read the .pcap file and extract certain fields out to a .csv file.

If there is any attack detected in some part of the packet capture file, the IDS prints the type of attack and the time of its execution. For example, the below screenshot is the result of giving the commit.pcapng file as input the the IDS.


![image](https://user-images.githubusercontent.com/44478153/130197090-493e7095-f88d-49c0-a84d-c428859a4967.png)
