from statistics import mode
import numpy as np
from scapy.all import sniff, Dot11ProbeReq
import math 
import csv
import time
from threading import Thread
from multiprocessing import Process
import os


rssi1 = list()

def callback(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        # print (" MAC ADRESS: %s RSSI: %s" %(pkt.addr2, pkt.dBm_AntSignal))

        if pkt.addr2 == "0c:a8:a7:69:a1:8c":
            # global rssi1
            rssi = pkt.dBm_AntSignal
            # print (rssi) #ReceivedSignalStrengthIndicator
            l = 67.6 #2400mhzFreq
            n = 4 #PathLossEnv
            txPower = 42
            # hasil = math.pow(10, (txPower - rssi - l) / (10 * n))
            hasil = math.pow(10, (txPower - rssi -l) / (10 * n))

            # print (rssi)
            # print (hasil, "meter")
            rssi1.append(hasil)
        else : 
            try:
                print("jarak Sebenarnya1",mode(rssi1))
                # print("jarak Sebenarnya2",(rssi1[-1]))
                print ("=========")
            except Exception:
                pass
            rssi1.clear()
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

# def print_all():
#     bisa()


 
if __name__ == '__main__':
    Thread(target = bisa).start()
    # Thread(target = printsq).start()    





    

