from scapy.all import *
from screen_manager import ScreenManager


if __name__ == "__main__":

    class NetNet:

        def __init__(self):
            screen_manager = ScreenManager()

    def all_info(pkt):
        return pkt.show()

    def filtered(pkt):
        for packet in pkt:
            print("OhhhhYa")
        return pkt.sprintf("{IP: IPV4: %IP.src% -> %IP.dst%\n}"
                           "{TCP: TCP Port: %TCP.sport% -> %TCP.dport%\n}"
                           "{UDP: UDP Port: %UDP.sport% -> %UDP.dport%\n}")

    sniff(prn=filtered)
