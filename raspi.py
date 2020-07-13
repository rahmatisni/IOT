from statistics import mode
import numpy as np
from scapy.all import sniff, Dot11ProbeReq
import math 
import csv
import time

# rssi1 = list()

def handle_packet(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        # print (" MAC ADRESS: %s RSSI: %s" %(pkt.addr2, pkt.dBm_AntSignal))

        if pkt.addr2 == "0c:a8:a7:69:a1:8c":
            # global rssi1
            rssi = pkt.dBm_AntSignal
            # print (rssi) #ReceivedSignalStrengthIndicator
            l = 67.6 #2400mhzFreq
            n = 4 #PathLossEnv
            txPower = 34
            hasil = math.pow(10, (txPower - rssi - l) / (10 * n))
            print (rssi)
            print (hasil, "meter")
            with open('1_meter.csv', 'w') as csvfile:
                fieldnames = ['rssi', 'meter']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerow({'rssi': rssi, 'meter': hasil})
        #     rssi1.append(hasil)
        # else : 
        #     try:
        #         print("jarak Sebenarnya",mode(rssi1))
        #     except Exception:
        #         pass
        #     rssi1.clear()
sniff(iface="wlan1mon", prn = handle_packet)




    

