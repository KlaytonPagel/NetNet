import requests


# Class that sends a message to the discord server at the URL
class DiscordAlert:

    # Set up alert system with the url and header
    def __init__(self):
        self.url = "Server URL"
        self.headers = {"authorization": "Headers Authorization"}

    # Use passed in message and send the post to the server
    def send_alert(self, message):
        message = {"content": f"{message}"}
        requests.post(self.url, message, headers=self.headers)
