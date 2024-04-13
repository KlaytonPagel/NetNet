from scapy.all import *


if __name__ == "__main__":
    sniff(prn=lambda x:x.show())
