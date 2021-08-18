#!/usr/bin/env python
# coding: utf-8

# In[19]:


bssid = "30:86:2d:c0:07:c0" #input("Please enter AP MAC addr: ") If small alphabets give an error, use capital instead e.g.- 30:86:2D:C0:07:C0
ssid = "WPA3" #input("Please enter target AP SSID: ") 


class beacon:    
    def __init__(self,time,interval,akmc,akmt):
        self.beacon_time = time
        self.beacon_int = interval
        self.akmcount = akmc
        self.akmtype = akmt
    def set_val(self,time,interval,akmc,akmt):
        self.beacon_time = time
        self.beacon_int = interval
        self.akmcount = akmc
        self.akmtype = akmt
        
class auth:
    def __init__(self,addr,seqno):
        self.addr = addr
        self.seqno = seqno
    def set_val(self,addr,seqno):
        self.addr = addr
        self.seqno = seqno        
        
import re

def mac_to_int(mac):
    res = re.match('^((?:(?:[0-9a-f]{2}):){5}[0-9a-f]{2})$', mac.lower())
    if res is None:
        raise ValueError('invalid mac address')
    return int(res.group(0).replace(':', ''), 16)        



print("Looking for any Attacks. Format: Type of attack detected <space> Time of Attack")
print("")

import os

#Enter the name of the input pcap file to be given below. Here below the 'group_unsupp.pcapng' pcap file is being given as input.
cmd2 = "tshark -r group_unsupp.pcapng -T fields -e frame.number -e frame.time -e wlan.sa -e wlan.ra -e frame.len -e wlan.fc.retry -e wlan.bssid -e wlan.seq -e wlan_radio.channel -e wlan.fc.type -e wlan.fc.subtype -e wlan.fixed.timestamp -e wlan.fixed.beacon -e wlan.ssid -e wlan.rsn.akms.count -e wlan.rsn.akms.type -e wlan.fixed.auth.alg -e wlan.fixed.auth_seq -e wlan.fixed.status_code -e wlan.fixed.sae_message_type -e wlan.fixed.finite_cyclic_group -e wlan.fixed.aid -e wlan.fixed.reason_code -e eapol.keydes.type -e wlan_rsna_eapol.keydes.msgnr -E header=y -E separator=, -E quote=d -E occurrence=f > test.csv"
os.system(cmd2)


# In[22]:

import pandas as pd
import numpy as np
import datetime
from datetime import timedelta
datetimeFormat = '%b %d, %Y %H:%M:%S.%f'

df = pd.read_csv ('test.csv')

# In[23]:


no_auth_frames = 8 #set to desired value
no_abnorm_events = 20 #set to desired value

b1 = beacon(-1,-1,-1,-1)
b2 = beacon(-1,-1,-1,-1)
b_ssid = np.empty(0)
b_mac = np.empty(0)
b_mode = 0 # 0 = learning mode, 1 = detection mode
b_abnorm = np.ones((1,4))
b_abnorm = b_abnorm+100
b_count = 0
b_time = 0
a1 = auth(-1,-1)
a2 = auth(-1,-1)
count = 0
count_time = 0

auth_arr = np.ones((1,no_auth_frames-1))
auth_arr = auth_arr+500
auth_time = -1
auth_count = 0
auth_counter = 0
auth_timer = -1
auth_count_time = 0
auth_abnorm = np.ones((1,no_abnorm_events-1))
auth_abnorm_arr = np.ones((1,no_auth_frames))
auth_abnorm = auth_abnorm+500
auth_check = np.empty(shape=(no_abnorm_events+1,no_auth_frames))
auth_check_time = []
auth_verify = []
auth_rej_arr = np.empty(0)
auth_rej_time = np.empty(0)
auth_rej_code = np.empty(0)
auth_timing = np.empty(0)

asso_arr = np.empty(0)
asso_time = np.empty(0)
asso_state = np.empty(0)

deauth_arr = np.empty(0)
deauth_time = np.empty(0)
deauth_count = 0


# In[24]:


for i in range(len(df)):
    if b_mode == 0: #if in learning mode
        if b_time == 0:
            b_time = df.loc[i].at['frame.time'][0:28]
        b_time_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(b_time, datetimeFormat)
        if b_time_diff.seconds > 120:
            b_mode = 1
        
    if df.loc[i].at['wlan.bssid'] != bssid:
        continue
    else:
        if len(auth_verify) != 0:
                i = 0
                while i<len(auth_verify):
                    auth_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(auth_check_time[i], datetimeFormat)
                    if auth_diff.seconds > 90:
                        print('Authentication flood attack detected',auth_check_time[i])
                        del auth_check_time[i]
                        del auth_verify[i]
                        auth_timing = np.empty(0)
                        i = i-1
                    i = i+1    
        if auth_rej_arr.size != 0:
                auth_rej_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(auth_rej_time[auth_rej_time.size-1], datetimeFormat)
                if auth_rej_diff.seconds > 2:
                    auth_rej_arr = np.empty(0)
                    auth_rej_time = np.empty(0)
                    auth_rej_code = np.empty(0)

        if df.loc[i].at['wlan.fc.type'] == 0: #Management frame
            
            if df.loc[i].at['wlan.fc.subtype'] == 8 or df.loc[i].at['wlan.fc.subtype'] == 5: #beacon or probe response
                integer = mac_to_int(df.loc[i].at['wlan.sa'])    
                if b_mode == 0: #learning mode
                    b_ssid = np.append(b_ssid,df.loc[i].at['wlan.ssid'])
                    b_mac = np.append(b_mac,integer)
                else: #detection mode
                    if not(integer in b_mac) or not(df.loc[i].at['wlan.ssid'] in b_ssid):
                        if b_count == 0:
                            b_time = df.loc[i].at['frame.time'][0:28]
                            b_count = b_count+1
                        else:
                            b_time_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(b_time, datetimeFormat)
                            b_time = df.loc[i].at['frame.time'][0:28]
                            b_abnorm = np.insert(b_abnorm, b_abnorm.size, (b_time_diff.seconds)+(b_time_diff.microseconds/1000000),1)
                            b_abnorm = np.delete(b_abnorm, 0, axis=1)
                            if b_abnorm.sum()<10: #10seconds
                                print('Beacon flood attack detected',df.loc[i].at['frame.time'])
                                b_abnorm = np.ones((1,4))
                                b_abnorm = b_abnorm+100
                                b_count = 0
                         
                # On restart/new AP, set b_time and b_mode appropriately
                
                if df.loc[i].at['wlan.sa'] == bssid and df.loc[i].at['wlan.ssid'] == ssid:
                    
                    b1.set_val(b2.beacon_time,b2.beacon_int,b2.akmcount,b2.akmtype)
                    b2.set_val(df.loc[i].at['frame.time'][0:28],df.loc[i].at['wlan.fixed.beacon'],df.loc[i].at['wlan.rsn.akms.count'],df.loc[i].at['wlan.rsn.akms.type'])
                    
                    if b1.beacon_int == -1:
                        continue
                    
                    time_diff = datetime.datetime.strptime(b2.beacon_time, datetimeFormat)- datetime.datetime.strptime(b1.beacon_time, datetimeFormat)
                    
                    if time_diff.seconds > 10:
                        count =0
                        count_time=0
                        continue
                    
                    else:
                        if b2.akmcount != b1.akmcount or b2.akmtype < b1.akmtype:
                            if count == 0:
                                count = count+1
                                count_time = df.loc[i].at['frame.time'][0:28]
                            elif count <= 2:
                                count = count+1
                            elif count == 3:    
                                diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(count_time, datetimeFormat)
                                if  diff.seconds < 5:
                                    count=count+1
                                else:
                                    count = 0
                            if count == 4:
                                print('WPA2 downgrade attack detected ',df.loc[i].at['frame.time'])
                                count = 0
                            
                        elif b2.beacon_int != b1.beacon_int:
                            a = 1
                            #print('beacon interval changed to ',df.loc[i].at['wlan.fixed.beacon'],'from ',b1.beacon_int, df.loc[i].at['frame.time'])
                        else:
                            continue
                        
            elif df.loc[i].at['wlan.fc.subtype'] == 11: #authentication
                
                if df.loc[i].at['wlan.sa'] == bssid or df.loc[i].at['wlan.fixed.sae_message_type'] != 1:
                    if df.loc[i].at['wlan.sa'] == bssid and df.loc[i].at['wlan.fixed.sae_message_type'] == 2:
                        integer = mac_to_int(df.loc[i].at['wlan.ra'])
                        if len(auth_verify) != 0:
                            i = 0
                            while i <len(auth_verify):
                                if integer in auth_verify[i]:
                                    auth_verify[i][no_abnorm_events][0] = auth_verify[i][no_abnorm_events][0] +1
                                if auth_verify[i][no_abnorm_events][0] >= (no_abnorm_events*no_auth_frames)/3:
                                    del auth_verify[i]
                                    del auth_check_time[i]
                                    i = i-1  
                                i = i+1
                        if integer in auth_timing:
                            index = np.where(auth_timing == integer)
                            auth_timing = np.delete(auth_timing,index[0][0])
                    if df.loc[i].at['wlan.sa'] == bssid and df.loc[i].at['wlan.fixed.sae_message_type'] == 1:
                        if df.loc[i].at['wlan.fixed.status_code'] == 77 or df.loc[i].at['wlan.fixed.status_code'] == 1 :
                            auth_rej_arr = np.append(auth_rej_arr,df.loc[i].at['wlan.ra'])
                            auth_rej_time = np.append(auth_rej_time,df.loc[i].at['frame.time'][0:28])
                            auth_rej_code = np.append(auth_rej_code,df.loc[i].at['wlan.fixed.status_code'])
                        if df.loc[i].at['wlan.fixed.status_code'] == 0:
                            if (df.loc[i].at['wlan.ra'] in auth_rej_arr):
                                index = np.where(auth_rej_arr == df.loc[i].at['wlan.ra'])
                                auth_rej_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(auth_rej_time[index[0][0]], datetimeFormat)
                                if (auth_rej_diff.seconds + auth_rej_diff.microseconds/1000) < 500: #500 milliseconds
                                    if auth_rej_code[index[0][0]] == 77:
                                        print('Group Unsupported attack detected',df.loc[i].at['frame.time'])
                                    else: 
                                        print('Commit Value out of range attack  detected',df.loc[i].at['frame.time'])
                                auth_rej_arr = np.delete(auth_rej_arr,index[0][0])
                                auth_rej_time = np.delete(auth_rej_time,index[0][0])
                                auth_rej_code = np.delete(auth_rej_code,index[0][0])
                    continue            
                    
                #-------------------
                a1.set_val(a2.addr,a2.seqno)
                a2.set_val(df.loc[i].at['wlan.sa'],df.loc[i].at['wlan.seq'])
                
                if a1.addr != a2.addr and a2.seqno == a1.seqno+1:
                    if auth_counter == 0:
                        auth_timer = df.loc[i].at['frame.time'][0:28]
                    auth_counter = auth_counter+1
                    auth_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(auth_timer, datetimeFormat)
                    if auth_counter == 2 and auth_diff.seconds<10:
                        print('Authentication flood attack detected',df.loc[i].at['frame.time'])
                        auth_counter = 0
                #--------------------
                
                if auth_time == -1:
                    auth_time = df.loc[i].at['frame.time'][0:28]
                    continue
                
                auth_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(auth_time, datetimeFormat)
                auth_time = df.loc[i].at['frame.time'][0:28]
                
                auth_arr = np.insert(auth_arr, auth_arr.size, (auth_diff.seconds*1000)+(auth_diff.microseconds/1000),1)
                auth_arr = np.delete(auth_arr, 0, axis=1)
                integer = mac_to_int(df.loc[i].at['wlan.sa'])
                auth_abnorm_arr = np.insert(auth_abnorm_arr, auth_abnorm_arr.size, integer,1)
                auth_abnorm_arr = np.delete(auth_abnorm_arr, 0, axis=1)
                auth_timing = np.append(auth_timing,integer)
                if auth_timing.size > 500:
                    print('Timing Side Channel attack detected',df.loc[i].at['frame.time'])
                    auth_timing = np.empty(0)
                
                if auth_arr.sum() < 500: #in milliseconds
                    if auth_count == 0:
                        auth_count_time = df.loc[i].at['frame.time'][0:28]
                        auth_check[auth_count] = auth_abnorm_arr
                        auth_count = (auth_count+1)%no_abnorm_events
                    else:
                        auth_check[auth_count] = auth_abnorm_arr
                        auth_count = (auth_count+1)%no_abnorm_events
                        auth_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(auth_count_time, datetimeFormat)
                        auth_count_time = df.loc[i].at['frame.time'][0:28]
                        auth_abnorm = np.insert(auth_abnorm, auth_abnorm.size, (auth_diff.seconds)+(auth_diff.microseconds/1000000),1)
                        auth_abnorm = np.delete(auth_abnorm, 0, axis=1)
                        if auth_abnorm.sum()<120: #in seconds
                            #print('Authentication flood attack detected',df.loc[i].at['frame.time'])
                            auth_check_time.append(df.loc[i].at['frame.time'][0:28])
                            auth_check[no_abnorm_events][0] = 0
                            auth_verify.append(auth_check)
                            auth_count = 0
                            auth_count_time = 0
                            auth_abnorm = np.ones((1,no_abnorm_events-1))
                            auth_abnorm = auth_abnorm+500
                    auth_arr = np.ones((1,no_auth_frames-1))
                    auth_arr = auth_arr+500    

            elif df.loc[i].at['wlan.fc.subtype'] == 0 or df.loc[i].at['wlan.fc.subtype'] == 1: #assosciation
                if deauth_arr.size != 0:
                    if (df.loc[i].at['wlan.sa'] in deauth_arr):
                        index = np.where(deauth_arr == df.loc[i].at['wlan.sa'])
                    elif (df.loc[i].at['wlan.ra'] in deauth_arr):
                        index = np.where(deauth_arr == df.loc[i].at['wlan.ra'])
                    else:
                        deauth_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(deauth_time[deauth_time.size-1], datetimeFormat)
                        if deauth_diff.seconds > 10:
                            deauth_arr = np.empty(0)
                            deauth_time = np.empty(0)
                        continue    
                    
                    deauth_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(deauth_time[index[0][0]], datetimeFormat)
                    if deauth_diff.seconds < 5: #5seconds
                        print('Deauthentication attack detected',df.loc[i].at['frame.time'])
                    deauth_arr = np.delete(deauth_arr,index[0][0])
                    deauth_time = np.delete(deauth_time,index[0][0])
                 
                if df.loc[i].at['wlan.fc.subtype'] == 0:
                    asso_arr = np.append(asso_arr,df.loc[i].at['wlan.sa'])
                    asso_time = np.append(asso_time,df.loc[i].at['frame.time'][0:28])
                    asso_state = np.append(asso_state,0)
                else :
                    if (df.loc[i].at['wlan.ra'] in asso_arr):
                        index = np.where(asso_arr == df.loc[i].at['wlan.ra'])
                        if df.loc[i].at['wlan.fixed.status_code'] == 0:
                            asso_state[index[0][0]] = 1
                    
                
            elif df.loc[i].at['wlan.fc.subtype'] == 12: #deauthentication
                if df.loc[i].at['wlan.sa'] == bssid:
                    deauth_arr = np.append(deauth_arr,df.loc[i].at['wlan.ra'])
                else:
                    deauth_arr = np.append(deauth_arr,df.loc[i].at['wlan.sa'])
                deauth_time = np.append(deauth_time,df.loc[i].at['frame.time'][0:28])
                
                if deauth_arr[deauth_arr.size - 1] in asso_arr:
                    index = np.where(asso_arr == deauth_arr[deauth_arr.size - 1])
                    asso_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(asso_time[index[0][0]], datetimeFormat)
                    if asso_diff.seconds < 5 and asso_state[index[0][0]] == 1:
                        deauth_count = deauth_count+1
                        if deauth_count == 3:
                            deauth_count = 0
                            print('Deauthentication attack detected',df.loc[i].at['frame.time'])
                    asso_arr = np.delete(asso_arr,index[0][0])
                    asso_time = np.delete(asso_time,index[0][0])
                    asso_state = np.delete(asso_state,index[0][0])
                else:
                    if asso_arr.size != 0:
                        asso_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(asso_time[asso_time.size-1], datetimeFormat)
                        if asso_diff.seconds > 5:
                            asso_arr = np.empty(0)
                            asso_time = np.empty(0)
                            asso_state = np.empty(0)    

                
            elif df.loc[i].at['wlan.fc.subtype'] == 10: #disassociation
                a= 1
            else:
                continue
                
        elif df.loc[i].at['wlan.fc.type'] == 2 and df.loc[i].at['eapol.keydes.type'] == 2: #Eapol
            if deauth_arr.size != 0:
                if (df.loc[i].at['wlan.sa'] in deauth_arr):
                    index = np.where(deauth_arr == df.loc[i].at['wlan.sa'])
                elif (df.loc[i].at['wlan.ra'] in deauth_arr):
                    index = np.where(deauth_arr == df.loc[i].at['wlan.ra'])
                else:
                    deauth_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(deauth_time[deauth_time.size-1], datetimeFormat)
                    if deauth_diff.seconds > 10:
                        deauth_arr = np.empty(0)
                        deauth_time = np.empty(0)
                    continue
                    
                deauth_diff = datetime.datetime.strptime(df.loc[i].at['frame.time'][0:28], datetimeFormat)- datetime.datetime.strptime(deauth_time[index[0][0]], datetimeFormat)
                if deauth_diff.seconds < 5: #5seconds
                    a=1
                    print('Deauthentication attack detected',df.loc[i].at['frame.time'])
                deauth_arr = np.delete(deauth_arr,index[0][0])
                deauth_time = np.delete(deauth_time,index[0][0])
                
        else:
            continue


