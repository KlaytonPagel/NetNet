from tkinter import *
from scapy.all import *


# Manage the different screens and windows______________________________________________________________________________
class ScreenManager:

    # Initial window set up_____________________________________________________________________________________________
    def __init__(self):
        # Set up window____________________________________
        self.screen = Tk()
        self.screen.title("NetNet")
        self.screen.geometry(f'{self.screen.winfo_screenwidth() // 2}x{self.screen.winfo_screenheight() // 1.5:.0f}')

        # Holds all widgets on the screen__________________
        self.on_screen = []

        # Set up the main screen___________________________
        self.traffic_frame = None
        self.main_screen()

        # Set up the packet sniffer________________________
        self.sniffer = AsyncSniffer(prn=self.add_packets)

        self.screen.mainloop()

    # Clears all the widgets from the screen____________________________________________________________________________
    def clear_screen(self):
        for widget in self.on_screen:
            widget.destroy()
        self.on_screen = []

    # Build The Main Startup Window_____________________________________________________________________________________
    def main_screen(self):
        self.clear_screen()

        # Navigation Bar frame_____________________________
        nav_bar = Frame(self.screen, width=self.screen.winfo_screenwidth())
        self.on_screen.append(nav_bar)
        nav_bar.pack(fill=X)

        # Start Button to start Sniffing___________________
        start_button = Button(nav_bar, text="Start", command=lambda: self.sniffer.start())
        self.on_screen.append(start_button)
        start_button.pack(side=LEFT)

        # Stop Button to start Sniffing____________________
        stop_button = Button(nav_bar, text="Stop", command=lambda: self.sniffer.stop())
        self.on_screen.append(stop_button)
        stop_button.pack(side=LEFT)

        # Title Label______________________________________
        title = Label(self.screen, text="NetNet", font=("arial", 25))
        self.on_screen.append(title)
        title.pack()

        # Frame for Network traffic________________________
        self.traffic_frame = Frame(self.screen, bg="Blue")
        self.on_screen.append(self.traffic_frame)
        self.traffic_frame.pack(fill=X)

    # Adds A Button For A Packet To The Traffic Frame___________________________________________________________________
    def add_packets(self, pkt):
        packet_button = Button(self.traffic_frame, text=pkt.sprintf("{IP: IPV4: %IP.src% -> %IP.dst%}"
                           "{TCP: TCP Port: %TCP.sport% -> %TCP.dport%}"
                           "{UDP: UDP Port: %UDP.sport% -> %UDP.dport%}"))
        self.on_screen.append(packet_button)
        packet_button.pack()
        return


ScreenManager()
