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


networks = pd.DataFrame(columns=["BSSID", "dBm_Signal", "meter"])
networks.set_index("BSSID", inplace=True)

def callback(packet):
    if packet.addr2 == "0c:a8:a7:69:a1:8c":
    # global rssi1
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        
        bssid = packet.addr2
        # print (rssi) #ReceivedSignalStrengthIndicator
        l = 67.6 #2400mhzFreq
        n = 4 #PathLossEnv
        txPower = 40
        meter = math.pow(10, (txPower - dbm_signal -l) / (10 * n))
        networks.loc[bssid] = (dbm_signal,meter)

def change_channel1():
    os.system(f"iwconfig wlan1mon channel 11")

def bisa ():
    # interface name, check using iwconfig
    interface = "wlan1mon"
    channel_changer = Thread(target=change_channel1)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=interface)

def print_all():
    while True:
        os.system("clear")
        print(networks)    
        time.sleep(1)

if __name__ == '__main__':
    Thread(target = bisa).start()
    print_all()