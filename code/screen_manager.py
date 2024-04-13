from tkinter import *


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

        self.main_screen()

        self.screen.mainloop()

    # Clears all the widgets from the screen____________________________________________________________________________
    def clear_screen(self):
        for widget in self.on_screen:
            widget.destroy()

    # Build The Main Startup Window_____________________________________________________________________________________
    def main_screen(self):
        self.clear_screen()

        # Navigation Bar frame_____________________________
        nav_bar = Frame(self.screen, width=self.screen.winfo_screenwidth())
        nav_bar.pack_propagate(False)
        self.on_screen.append(nav_bar)
        nav_bar.pack()

        # Start Button to start scraping___________________
        start_button = Button(nav_bar, text="Start")
        self.on_screen.append(start_button)
        start_button.pack()

        # Title Label______________________________________
        title = Label(self.screen, text="NetNet", font=("arial", 25))
        self.on_screen.append(title)
        title.pack()

        # Frame for Network traffic________________________
        traffic_frame = Frame(self.screen, width=self.screen.winfo_screenwidth(),
                              height=self.screen.winfo_screenheight())
        traffic_frame.pack_propagate(False)
        self.on_screen.append(traffic_frame)
        traffic_frame.pack()


ScreenManager()
