import json
import requests
from threading import Thread
from multiprocessing import Process
from scapy.all import *
import pandas as pd
import numpy
import time
import os
import localization as lx

# initialize the networks dataframe that will contain all access points nearby
networks = pd.DataFrame(columns=["BSSID", "dBm_Signal", "meter"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
# initialize the networks dataframe that will contain all access points nearby
networks2 = pd.DataFrame(columns=["BSSID", "dBm_Signal2", "meter2"])
# set the index BSSID (MAC address of the AP)
networks2.set_index("BSSID", inplace=True)
# initialize the networks dataframe that will contain all access points nearby
networks3 = pd.DataFrame(columns=["BSSID", "dBm_Signal3", "meter3"])
# set the index BSSID (MAC address of the AP)
networks3.set_index("BSSID", inplace=True)
networks3.loc["0c:a8:a7:69:a1:8c"] = (-30,1)

def callback(packet):
    if packet.haslayer(Dot11ProbeReq):
        if packet.addr2 == "0c:a8:a7:69:a1:8c":

            # extract the MAC address of the networks
            bssid = packet.addr2
            # get the name of it
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            
            n = 10 #PathLossEnv
            txPower = 0
            meter = math.pow(10, (txPower - dbm_signal) / (10 * n))
            networks.loc[bssid] = (dbm_signal,meter)

def callback2(packet):
    if packet.haslayer(Dot11ProbeReq):
        if packet.addr2 == "0c:a8:a7:69:a1:8c":

            # extract the MAC address of the networks
            bssid = packet.addr2
            # get the name of it
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            
            n = 10 #PathLossEnv
            txPower = 0
            meter = math.pow(10, (txPower - dbm_signal) / (10 * n))
            networks2.loc[bssid] = (dbm_signal,meter)

def callback3(packet):
    if packet.haslayer(Dot11ProbeReq):
        if packet.addr2 == "0c:a8:a7:69:a1:8c":

            # extract the MAC address of the networks
            bssid = packet.addr2
            # get the name of it
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            
            n = 10 #PathLossEnv
            txPower = 20
            meter = math.pow(10, (txPower - dbm_signal) / (10 * n))
            # networks3.loc[bssid] = (dbm_signal,meter)

def print_all():
    while True:
        os.system("clear")
        # print(networks)    
        pd.concat([networks, networks2, networks3], axis=1, sort=False)
        result = pd.concat([networks, networks2, networks3], axis=1, sort=False)
        print(result)
        val1 = result['meter'].values[0]
        val2 = result['meter2'].values[0]
        val3 = result['meter3'].values[0]
        
        P=lx.Project(mode='2D',solver='LSE')
        P.add_anchor('anchore_A',(1,1))
        P.add_anchor('anchore_B',(5,9))
        P.add_anchor('anchore_C',(10,2))

        t,label=P.add_target()

        t.add_measure('anchore_A',val1)
        t.add_measure('anchore_B',val2)
        t.add_measure('anchore_C',val3)

        P.solve()
        print(t.loc)
        data = {'X': t.loc.x, 'Y' : t.loc.y}
        koor = json.dumps(data)
        with open('koor_user.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print (koor)

        time.sleep(0.5)


def change_channel1():
    ch = 11
    os.system(f"iwconfig {wlan1mon} channel {ch}")
def change_channel2():    
    ch = 11
    os.system(f"iwconfig {wlan2mon} channel {ch}")
def change_channel3():
    ch = 11
    os.system(f"iwconfig {wlan3mon} channel {ch}")

def bisa ():
    # interface name, check using iwconfig
    interface = "wlan1mon"
    channel_changer = Thread(target=change_channel1)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=interface)
def bisa2 ():
    # interface name, check using iwconfig
    interface = "wlan2mon"
    channel_changer = Thread(target=change_channel2)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback2, iface=interface)
    
def bisa3 ():
    # interface name, check using iwconfig
    interface = "wlan3mon"
    channel_changer = Thread(target=change_channel3)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback3, iface=interface)


if __name__ == '__main__':
    Thread(target = bisa).start()
    Thread(target = bisa2).start()
    Thread(target = bisa3).start()
    print_all()
















# def sendapi():

#     url = "http://localhost:3000/asd"

#     payload = 'jarak1=3.2323232&jarak2=8.4141414141&jarak3=6.234242424&mac=0c%3Aa8%3Aa7%3A69%3Aa1%3A8c'
#     headers = {
#     'Content-Type': 'application/x-www-form-urlencoded'
#     }

#     response = requests.request("POST", url, headers=headers, data = payload)

#     print(response.text.encode('utf8'))

# sendapi()