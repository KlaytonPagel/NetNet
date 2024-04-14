from tkinter import *
from scapy.all import *
from functools import partial
from datetime import *


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
            self.packets = []

            # Set up the main screen_______________________
            self.traffic_frame = None
            self.canvas = None
            self.scrollbar = None
            self.container = None
            self.built = False
            self.main_screen()

            # Set up the packet sniffer____________________
            self.sniffer = AsyncSniffer(prn=self.add_packets)

            self.screen.mainloop()

        # Clears all the widgets from the screen________________________________________________________________________
        def clear_screen(self, clear_traffic=False):

            # Stop the sniffer if it's running_____________
            try:
                self.sniffer.stop()
            except:
                pass

            # Clear widgets from the screen________________
            for widget in self.on_screen:
                widget.destroy()
            self.on_screen = []

            # If clear traffic is on destroy packet buttons
            if clear_traffic:
                self.built = False
                for packet in self.captured:
                    packet.destroy()
                self.captured = []
                for packet in self.packets:
                    packet.destroy()
                self.packets = []

        def scroll_bar_config(self, event):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        # Build The Main Startup Window_________________________________________________________________________________
        def main_screen(self):
            self.clear_screen()

            # Navigation Bar frame_________________________
            nav_bar = Frame(self.screen, width=self.screen.winfo_screenwidth(), relief="groove")
            self.on_screen.append(nav_bar)
            nav_bar.pack(fill=X)

            # Start Button to start Sniffing_______________
            start_button = Button(nav_bar, text="Start", font=("arial", 15), command=lambda: [self.sniffer.start()])
            self.on_screen.append(start_button)
            start_button.pack(side=LEFT)

            # Stop Button to stop Sniffing_________________
            stop_button = Button(nav_bar, text="Stop", font=("arial", 15), command=lambda: self.sniffer.stop())
            self.on_screen.append(stop_button)
            stop_button.pack(side=LEFT)

            # Button to clear the packets from screen______
            clear_button = Button(nav_bar, text="Clear", font=("arial", 15), command=lambda: [self.clear_screen(True),
                                                                                              self.main_screen()])
            self.on_screen.append(clear_button)
            clear_button.pack(side=LEFT)

            # Title Label__________________________________
            title = Label(self.screen, text="NetNet", font=("arial", 25))
            self.on_screen.append(title)
            title.pack()

            # Set up scroll box for network traffic________
            if not self.built:
                self.built = True
                self.container = Frame(self.screen, relief=GROOVE, bd=5)
                self.captured.append(self.container)

                self.canvas = Canvas(self.container)
                self.captured.append(self.canvas)

                self.traffic_frame = Frame(self.canvas)
                self.captured.append(self.traffic_frame)

                self.scrollbar = Scrollbar(self.container, orient="vertical", command=self.canvas.yview)
                self.canvas.configure(yscrollcommand=self.scrollbar.set)
                self.captured.append(self.scrollbar)

                self.canvas.create_window((self.screen.winfo_screenwidth()//4, 0), window=self.traffic_frame)
                self.traffic_frame.bind("<Configure>",
                                        lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all"),
                                                                            width=self.screen.winfo_screenwidth(),
                                                                            height=self.canvas.winfo_screenheight()))

            self.container.pack(fill=BOTH, expand=True)
            self.scrollbar.pack(side="right", fill="y")
            self.canvas.pack()

        # Adds A Button For A Packet To The Traffic Frame_______________________________________________________________
        def add_packets(self, pkt):
            data = pkt.show(dump=True)
            name = pkt.sprintf(f"{datetime.today().strftime('%H:%M:%S.%f')}\t"
                               "{IP: IPV4: %IP.src% -> %IP.dst%\t}"
                               "{TCP: TCP Port: %TCP.sport% -> %TCP.dport%\t}"
                               "{UDP: UDP Port: %UDP.sport% -> %UDP.dport%\t}"
                               "{Ether: type: %Ether.type%}")
            packet_button = Button(self.traffic_frame, text=name, command=lambda: self.packet_details(data),
                                   width=self.screen.winfo_screenwidth())
            self.packets.append(packet_button)
            packet_button.pack()
            self.canvas.yview_moveto(1)

        # Shows the data contained inside the packet____________________________________________________________________
        def packet_details(self, data):
            self.clear_screen()

            self.container.pack_forget()
            self.scrollbar.pack_forget()
            self.canvas.pack_forget()

            # Navigation Bar to hold all buttons___________
            nav_bar = Frame(self.screen)
            self.on_screen.append(nav_bar)
            nav_bar.pack(fill=X)

            # Button to return back to the main screen_____
            back_button = Button(nav_bar, text="Back", font=("arial", 15), command=self.main_screen)
            self.on_screen.append(back_button)
            back_button.pack(side=LEFT)

            # Entry Disabled entry box to display the packet data to the user
            data_entry = Text(self.screen, relief="groove")
            self.on_screen.append(data_entry)
            data_entry.insert(1.0, data)
            data_entry.configure(state=DISABLED)
            data_entry.pack(fill=BOTH, expand=True)


    ScreenManager()
