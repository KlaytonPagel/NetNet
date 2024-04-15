# NetNet
Network Net (NetNet) is a Network monitoring and alert system. It uses Scapy to sniff traffic and TKinter for the GUI. 

## Network Monitoring
To run NetNet you will have to download Npcap. it can be found at https://npcap.com/#download. From the main menu pressing start will start capturing traffic. you can select any of the packet displayed to open up detailed information about the traffic.

## Filters
From the main menu their is a filter menu button in the top right. This menu allows you to create several filters and save them to import later. You can select a previously made filter and load it to make changes. You can add several different parameters and enter values for them. To sniff traffic at the main menu you can select a filter and apply it before you start the sniffing. Clearing the screen will undo the filter.

## Alert System
NetNet's alert system sends any traffic being captured to a discord server. To send it to a discord server you will need to go to the alert.py file and set the URL variable to the URL of a discord webhook. To create a webhook go to your discord channel > edit channel > Integrations > Webhooks. From here you will creat a webhook and copy it's URL into the alert.py URL variable.
