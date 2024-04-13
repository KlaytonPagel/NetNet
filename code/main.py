from scapy.all import *


if __name__ == "__main__":
    # sniff(prn=lambda x:x.show())

    def traffic(pkt):
        return pkt.sprintf("{IP: IPV4 %IP.src% -> %IP.dst%\n}{TCP: Port: %TCP.sport% -> %TCP.dport%\n}")

    sniff(prn=traffic)
