from scapy.all import *
from threading import Thread
import pandas as pd
import time
import os

networks = pd.DataFrame(columns=["BSSID", "dBm_Signal", "meter"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

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
            
            n = 3 #PathLossEnv
            txPower = -20
            # power = 67.6
            meter = math.pow(10, (txPower - dbm_signal) / (10 * n))
            networks.loc[bssid] = (dbm_signal,meter)

def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = 11
        time.sleep(0.5)


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlan1mon"
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=interface)