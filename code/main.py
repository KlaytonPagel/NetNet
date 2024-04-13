from scapy.all import *
from screen_manager import ScreenManager


if __name__ == "__main__":

#     class NetNet:
#
#         def __init__(self):
#             self.screen_manager = ScreenManager()
#             sniff(prn=self.sniff)
#
#         def sniff(self, pkt):
#             for packet in pkt:
#                 print("OhhhhYa")
#             self.screen_manager.add_packets(pkt.sprintf("{IP: IPV4: %IP.src% -> %IP.dst%\n}"
#                                "{TCP: TCP Port: %TCP.sport% -> %TCP.dport%\n}"
#                                "{UDP: UDP Port: %UDP.sport% -> %UDP.dport%\n}"), "")
#
# NetNet()


    def all_info(pkt):
        return pkt.show()

    def filtered(pkt):
        print("OhhhhYa")
        return pkt.sprintf("{IP: IPV4: %IP.src% -> %IP.dst%\n}"
                           "{TCP: TCP Port: %TCP.sport% -> %TCP.dport%\n}"
                           "{UDP: UDP Port: %UDP.sport% -> %UDP.dport%\n}")

    sniff(prn=filtered)
