import datetime
import gc
from statistics import mode
import numpy as np
from scapy.all import sniff, Dot11ProbeReq
import math 
import csv
import time
from threading import Thread
from multiprocessing import Process
import os
import pandas as pd

networks = pd.DataFrame(columns=["BSSID", "dBm_Signal", "meter"])
networks.set_index("BSSID", inplace=True)
# networks.loc["bssid"] = ("Nan","Nan")

mac_addresss = ["0c:a8:a7:69:a1:8c", "b0:35:9f:37:e1:78"]
net_1 = {}
# net_2 = []
def callback(pkt, timeout = None):
    # print ("callback")
    
    # if pkt.haslayer(Dot11ProbeReq):
    for i in mac_addresss:
        global net_1
        if pkt.addr2 == (i):
            # print('loop mac',i,'terbaca')
            bssid = pkt.addr2
                # global rssi1
            rssi = pkt.dBm_AntSignal
            # print (rssi) #ReceivedSignalStrengthIndicator
            l = 67.6 #2400mhzFreq
            n = 2 #PathLossEnv
            txPower = 36
            # hasil = math.pow(10, (txPower - rssi - l) / (10 * n))
            meter = math.pow(10, (txPower - rssi -l) / (10 * n))
            networks.loc[bssid] = (rssi,meter)
            net_1.update({pkt.addr2 : "1", 'D'+pkt.addr2 : meter})
            print('Mac Berhasil distore')
            now = datetime.datetime.now()
            print ("Store AT : ", now)
        else :
            z=0
            # print('loop mac',i,'tidak terbaca')
            
            # try:
            #     l=(pkt.addr2,'D'+pkt.addr2)
            #     list(map(net_1.__delitem__, filter(net_1.__contains__,l)))
            #     print('Mac Berhasil dihapus')
            # except:
            #     print('Mac Sudah Terhapus')
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
    while True :
        # os.system("clear")
        # global net_1
        # print ("sudah di loop")
        # print(net_1)
        time.sleep(0.3)
        
if __name__ == '__main__':
    Thread(target = bisa).start()
    Thread(target = print_all).start()

# bisa()    