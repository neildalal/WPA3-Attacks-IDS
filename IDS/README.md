Our IDS code IDS_WPA3.py takes 3 inputs - the BSSID (MAC Address) of our target AP, the SSID set for our target AP and the packet capture file in which we want to detect attacks. These are set in the code at line 7, line 8 and line 47 respectively.
After changing these appropriate fields, simply run the python code in terminal as
```
python IDS_wPA3.py
```

Note: 
1) To be able to run this python file, some packages may need to be installed. For example, `tshark` is needed to read the .pcap file and extract certain fields out to a .csv file.
2) Currently the inputs that the IDS takes are coded in the python file itself, but it can be easily edited to take inputs from the terminal interactively rather than changing the inputs from code at line 7,8 and 47.
3) Also currently, the IDS takes only one .pcap file as input, but it can be easily edited to keep taking several .pcap files as input one after the other and maintaing its state in between.

If there is any attack detected in some part of the packet capture file, the IDS prints the type of attack and the time of its execution. For example, the below screenshot is the result of giving the commit.pcapng file as input the the IDS.


![image](https://user-images.githubusercontent.com/44478153/130197090-493e7095-f88d-49c0-a84d-c428859a4967.png)
