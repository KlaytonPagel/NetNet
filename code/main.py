from scapy.all import *
from tkinter import *


if __name__ == "__main__":

    def all_info(pkt):
        return pkt.show()

    def filtered(pkt):
        return pkt.sprintf("{IP: IPV4 %IP.src% -> %IP.dst%\n}{TCP: Port: %TCP.sport% -> %TCP.dport%\n}")

    sniff(prn=all_info)
