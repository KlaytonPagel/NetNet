from scapy.all import *
from screen_manager import ScreenManager


if __name__ == "__main__":

    class NetNet:

        def __init__(self):
            screen_manager = ScreenManager()

    def all_info(pkt):
        return pkt.show()

    def filtered(pkt):
        return pkt.sprintf("{IP: IPV4 %IP.src% -> %IP.dst%\n}{TCP: Port: %TCP.sport% -> %TCP.dport%\n}")

    sniff(prn=filtered)
