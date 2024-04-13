from tkinter import *
from scapy.all import *


if __name__ == "__main__":

    # Manage the different screens and windows__________________________________________________________________________
    class ScreenManager:

        # Initial window set up_________________________________________________________________________________________
        def __init__(self):
            # Set up window________________________________
            self.screen = Tk()
            self.screen.title("NetNet")
            self.screen.geometry(f'{self.screen.winfo_screenwidth() // 2}x{self.screen.winfo_screenheight() // 1.5:.0f}')

            # Holds all widgets on the screen______________
            self.on_screen = []
            self.captured = []

            # Set up the main screen_______________________
            self.traffic_frame = None
            self.main_screen()

            # Set up the packet sniffer____________________
            self.sniffer = AsyncSniffer(prn=self.add_packets)

            self.screen.mainloop()

        # Clears all the widgets from the screen________________________________________________________________________
        def clear_screen(self):
            try:
                self.sniffer.stop()
            except:
                pass
            for widget in self.on_screen:
                widget.destroy()
            self.on_screen = []
            for packet in self.captured:
                packet.pack_forget()

        # Build The Main Startup Window_________________________________________________________________________________
        def main_screen(self):
            self.clear_screen()

            # Navigation Bar frame_________________________
            nav_bar = Frame(self.screen, width=self.screen.winfo_screenwidth())
            self.on_screen.append(nav_bar)
            nav_bar.pack(fill=X)

            # Start Button to start Sniffing_______________
            start_button = Button(nav_bar, text="Start", font=("arial", 15), command=lambda: [self.main_screen(),
                                                                                              self.sniffer.start()])
            self.on_screen.append(start_button)
            start_button.pack(side=LEFT)

            # Stop Button to stop Sniffing_________________
            stop_button = Button(nav_bar, text="Stop", font=("arial", 15), command=lambda: self.sniffer.stop())
            self.on_screen.append(stop_button)
            stop_button.pack(side=LEFT)

            # Title Label__________________________________
            title = Label(self.screen, text="NetNet", font=("arial", 25))
            self.on_screen.append(title)
            title.pack()

            # Frame for Network traffic____________________
            # If there is no previously captured traffic
            if len(self.captured) == 0:
                self.traffic_frame = Frame(self.screen)
                self.captured.append(self.traffic_frame)
                self.traffic_frame.pack(fill=X)
            else:
                # Display any traffic that is still in the system
                for packet in self.captured:
                    packet.pack()

        # Adds A Button For A Packet To The Traffic Frame_______________________________________________________________
        def add_packets(self, pkt):
            data = pkt.show(dump=True)
            name = pkt.sprintf("{IP: IPV4: %IP.src% -> %IP.dst%}"
                               "{TCP: TCP Port: %TCP.sport% -> %TCP.dport%}"
                               "{UDP: UDP Port: %UDP.sport% -> %UDP.dport%}")
            packet_button = Button(self.traffic_frame, text=name, command=lambda: self.packet_details(data))
            self.captured.append(packet_button)
            packet_button.pack()
            return

        # Shows the data contained inside the packet____________________________________________________________________
        def packet_details(self, data):
            self.clear_screen()

            # Navigation Bar to hold all buttons___________
            nav_bar = Frame(self.screen)
            self.on_screen.append(nav_bar)
            nav_bar.pack(fill=X)

            # Button to return back to the main screen_____
            back_button = Button(nav_bar, text="Back", font=("arial", 15), command=self.main_screen)
            self.on_screen.append(back_button)
            back_button.pack(side=LEFT)

            # Entry Disabled entry box to display the packet data to the user
            data_entry = Text(self.screen)
            self.on_screen.append(data_entry)
            data_entry.insert(1.0, data)
            data_entry.configure(state=DISABLED)
            data_entry.pack(fill=BOTH, expand=True)


    ScreenManager()
