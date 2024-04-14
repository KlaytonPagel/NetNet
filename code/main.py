from tkinter import *
from scapy.all import *
from functools import partial
import datetime as datetime
import json


if __name__ == "__main__":

    # Manage the different screens and windows__________________________________________________________________________
    class NetNet:

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
            if self.built:
                self.container.pack_forget()
                self.scrollbar.pack_forget()
                self.canvas.pack_forget()

            self.stop_sniffing()
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

        # Stop Sniffing Network Traffic_________________________________________________________________________________
        def stop_sniffing(self):
            try:
                self.sniffer.stop()
            except:
                pass

        # Start Sniffing Network Traffic________________________________________________________________________________
        def start_sniffing(self):
            time.sleep(0.5)
            self.sniffer.start()

        # Build The Main Startup Window_________________________________________________________________________________
        def main_screen(self):
            self.clear_screen()

            # Navigation Bar frame_________________________
            nav_bar = Frame(self.screen, width=self.screen.winfo_screenwidth(), relief="groove")
            self.on_screen.append(nav_bar)
            nav_bar.pack(fill=X)

            # Start Button to start Sniffing_______________
            start_button = Button(nav_bar, text="Start", font=("arial", 15), command=lambda: [self.stop_sniffing(),
                                                                                              self.start_sniffing()])
            self.on_screen.append(start_button)
            start_button.pack(side=LEFT)

            # Stop Button to stop Sniffing_________________
            stop_button = Button(nav_bar, text="Stop", font=("arial", 15), command=lambda: self.stop_sniffing())
            self.on_screen.append(stop_button)
            stop_button.pack(side=LEFT)

            # Button to clear the packets from screen______
            clear_button = Button(nav_bar, text="Clear", font=("arial", 15), command=lambda: [self.clear_screen(True),
                                                                                              self.main_screen()])
            self.on_screen.append(clear_button)
            clear_button.pack(side=LEFT)

            # Button to go to the filter creation screen___
            filter_button = Button(nav_bar, text="Filters", font=("arial", 15), command=self.filter_screen)
            self.on_screen.append(filter_button)
            filter_button.pack(side=RIGHT)

            # Title Label__________________________________
            title = Label(self.screen, text="NetNet", font=("arial", 25))
            self.on_screen.append(title)
            title.pack()

            # Set up scroll box for network traffic________
            if not self.built:
                self.built = True

                # Container to hold the canvas and use scrollbar
                self.container = Frame(self.screen, relief=GROOVE, bd=5)
                self.captured.append(self.container)

                # canvas to make window for scrolling through the frame containing packet buttons
                self.canvas = Canvas(self.container)
                self.captured.append(self.canvas)

                # Frame to hold the packet buttons
                self.traffic_frame = Frame(self.canvas)
                self.captured.append(self.traffic_frame)

                # Scrollbar to move the canvas window across the traffic frame
                self.scrollbar = Scrollbar(self.container, orient="vertical", command=self.canvas.yview)
                self.canvas.configure(yscrollcommand=self.scrollbar.set)
                self.captured.append(self.scrollbar)

                # Create window and bind the traffic frame to it
                self.canvas.create_window((self.screen.winfo_screenwidth()//4, 0), window=self.traffic_frame)
                self.traffic_frame.bind("<Configure>",
                                        lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all"),
                                                                            width=self.screen.winfo_screenwidth(),
                                                                            height=self.canvas.winfo_screenheight()))

            # Pack everything to the screen to display to user
            self.container.pack(fill=BOTH, expand=True)
            self.scrollbar.pack(side="right", fill="y")
            self.canvas.pack()

        # Adds A Button For A Packet To The Traffic Frame_______________________________________________________________
        def add_packets(self, pkt):
            # Collects all data for the detailed note
            data = pkt.show(dump=True)
            # Formats what is displayed as the button name
            name = pkt.sprintf(f"{datetime.datetime.today().strftime('%H:%M:%S.%f')}\t"
                               "{IP: IPV4: %IP.src% -> %IP.dst%\t}"
                               "{TCP: TCP Port: %TCP.sport% -> %TCP.dport%\t}"
                               "{UDP: UDP Port: %UDP.sport% -> %UDP.dport%\t}"
                               "{Ether: type: %Ether.type%}")

            # Create the button widget and add it to the screen
            packet_button = Button(self.traffic_frame, text=name, command=lambda: self.packet_details_screen(data),
                                   width=self.screen.winfo_screenwidth())
            self.packets.append(packet_button)
            packet_button.pack()
            self.canvas.yview_moveto(1)

        # Shows the data contained inside the packet____________________________________________________________________
        def packet_details_screen(self, data):
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
            data_entry = Text(self.screen, relief="groove")
            self.on_screen.append(data_entry)
            data_entry.insert(1.0, data)
            data_entry.configure(state=DISABLED)
            data_entry.pack(fill=BOTH, expand=True)

        # Screen for making a filter____________________________________________________________________________________
        def filter_screen(self):
            def add_parameter():
                # add a frame for the parameter and value entries
                param_frame = Frame(self.screen)
                self.on_screen.append(param_frame)
                param_frame.pack()

                # option menu to select parameter type
                choice = StringVar()
                param = OptionMenu(param_frame, choice, *options)
                self.on_screen.append(param)
                param.pack(side=LEFT)

                # entry box for value of parameter
                entry = Entry(param_frame, font=("Arial", 12))
                self.on_screen.append(entry)
                entry.pack(side=RIGHT)

                # Store the parameter and value for saving later
                parameters.append([choice, entry])

            self.clear_screen()
            options = ["Source IP", "Destination IP", "Protocol"]
            parameters = []

            # Navigation Bar to hold all buttons___________
            nav_bar = Frame(self.screen)
            self.on_screen.append(nav_bar)
            nav_bar.pack(fill=X)

            # Button to return back to the main screen_____
            back_button = Button(nav_bar, text="Back", font=("arial", 15), command=self.main_screen)
            self.on_screen.append(back_button)
            back_button.pack(side=LEFT)

            # Button to save filter as a JSON file_________
            save_button = Button(nav_bar, text="Save", font=("arial", 15), command=lambda: self.save_filter(parameters,
                                                                                                            filter_name.get()))
            self.on_screen.append(save_button)
            save_button.pack(side=RIGHT)

            # Frame for filter name label and entry box____
            filter_name_frame = Frame(self.screen)
            self.on_screen.append(filter_name_frame)
            filter_name_frame.pack()

            # Label for the filter name____________________
            filter_name_label = Label(filter_name_frame, text="Filter Name")
            self.on_screen.append(filter_name_label)
            filter_name_label.pack(side=LEFT)

            # Entry To Name Your Filter____________________
            filter_name = Entry(filter_name_frame, font=("arial", 12))
            self.on_screen.append(filter_name)
            filter_name.pack(side=RIGHT)

            # Button to add another filter parameter_______
            add_param_button = Button(self.screen, text="Add Parameter", font=("arial", 12), command=add_parameter)
            self.on_screen.append(add_param_button)
            add_param_button.pack()

        # Save the filter in a JSON format______________________________________________________________________________
        def save_filter(self, parameters, filter_name):
            param_count = 0
            param_dict = {}

            # Put all filter inputs into a dictionary format to turn into JSON
            for param in parameters:
                param_dict[param_count] = [param[0].get(), param[1].get()]
                param_count += 1

            # Dump data to JSON and save to a file with the given name
            json_data = json.dumps(param_dict)
            with open(f"../Filters/{filter_name}", "w") as filter_file:
                filter_file.write(json_data)



    NetNet()
