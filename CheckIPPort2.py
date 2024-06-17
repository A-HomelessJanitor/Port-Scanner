#   CheckIPPort.py
#   Python 3.12.1 64-bit version
'''
Author :        Alexander Graham
Author email :  alexander.graham@gelosmail.com

Copyright Red Opal Innovations ©
Proprietary License

Creation: 6/06/2024
Last update: 14/06/2024
Version: 1.0.1
Status: In Development

Description: This script will be a home made port scanner designed to look through the specified
ip addresses and check the port status, the ports defined will be located in "ports.txt"
'''
# ---                                       imports & variable setting                                        --- #
import ipaddress
import datetime
import os
import sys
import win32evtlogutil
from socket import *

sys.tracebacklimit = 0

os.system("cls")    #used to clean up the terminal and make it pretty

def welcomeUserInput():
    print("""
# ---        Gelos Enterprises IP Port scannning tool        --- #\n
                --- FOR AUTHORISED USE ONLY ---\n
# ---                                                        --- #
\n""")

    print("PLEASE READ:\n\nIf this is your first time using this script\nplease make sure you are being supervised by a previous user.\n\n")
    try:
        net4Hosts = "1.1.1.0/27"  #input("Network   (A.B.C.D/##)  : ")        <--- old code
        net4List = [str(ip) for ip in ipaddress.IPv4Network(net4Hosts)] #makes a list of host ips from the net4Hosts input  and puts them in a list
    except ipaddress.AddressValueError:         
        os.system("cls")               #returns a error message to help the user address what they did wrong
        return(print("IP Address Value Error ! ! !\nDid you input a proper Network ID ?"))
    except ValueError:
        os.system("cls")               #returns a error message to help the user address what they did wrong
        return(print("Couldnt calculate a correct Host range ! ! !\nAre host bits in the Network ID ?"))
    except:
        os.system("cls")               #returns a error message to help the user address what they did wrong
        return(print("Script error ! ! !\nIf you want to close the script please close the terminal !"))

    listLengthCheck = len(net4List)         #checking if it is a usable subnet
    if listLengthCheck < 11:                #we cant use anything that doesnt have more than 11 addresses
        os.system("cls")
        return(print("Unusable IP range (please put in a length longer than 10 IPs)"))
   
    del net4List[:10]           #deleting the first 10 addresses
    del net4List[-1]            #deleting the last address
    net4UsableHosts = []        #creating a empty list to hold the useable functions
    for ip in net4List:
        if ((int(ip.split(".")[3]) % 2) == 1):
            net4UsableHosts.append(ip)
        #grabs the list of items in "list" var then slpits the ips by the ".", then we keep the 3rd index (4th octect) and in those numbers find out how many times
        #those numbers can be divided by 2, IF those numbers have a remander of 1 ie. you can put 2, 2 times into 5 but have a remainder of 1, it looks at the remainder of 1
        #and appends it into a new list of useable hosts, therefore not destroying any original data but manupulating it.   
    return(net4UsableHosts) 

def portScan():
    
    with open("ports.txt", "r") as f:       #open ports.txt
        ports = []
        ports = f.read().split("\n")    #put the list of ports into the ports var and seperate by line
        ports = list(map(int, ports))   #turn them into intigers
    
    suc_IPs_and_Ports = []
    
    print("scanning :", net4UsableHosts)
    
    for ip in net4UsableHosts:
        print("\n", ip)
        for port in ports:              #iterate through the IPs and ports
            s = socket(AF_INET, SOCK_STREAM,)   #the socket connection will be using IPV4 and sending out TCP Packets
            s.settimeout(1)                   
            result = s.connect_ex((ip,port))                #attempt a connection on the current ip and port in the interation
            s.close()                           #closing the connection if there is one  
                
            if result == 0:
                print("port {} is open ! ! ! ! !".format(port))         #printing the message in the terminal
                combo = "IP {} responded on port {}".format(ip, port)   #makeing a message for the log text file
                binary = bytes("Connection to {} on port {} was successful".format(ip,port), encoding="utf-8")      #this is the message that will be displayed in windows event viewer
                win32evtlogutil.ReportEvent(ip, 9999, eventType= 4, eventCategory=3, data=binary)    #sending the result to the event viewer
                suc_IPs_and_Ports.append(combo)

            else:
                print("port {} is closed".format(port))     #saying that the port is closed
                binary2 = bytes("Connection to {} on port {} was unsuccessful".format(ip,port), encoding="utf-8")   #this is the message that will be displayed in windows event viewer
                win32evtlogutil.ReportEvent(ip, 7040, eventType=2, eventCategory=3, data=binary2)   #sending result to event viewer
    
    return(suc_IPs_and_Ports)

# ---                     # --- #                DRIVER CODE                   # --- #                   --- #

if __name__ == '__main__':
    
    net4UsableHosts = welcomeUserInput()
    while net4UsableHosts == None:
        net4UsableHosts = welcomeUserInput()            #making a loop to keep asking for a good ip range
        if net4UsableHosts != None:
            break

    portScanResult = portScan()
    
    with open("ip_port_log.txt", "a") as f:             # appending the results of the port scan into the log file
        current_time = datetime.datetime.now()          # adding date and time
        f.write("\n{}\n".format(current_time) )
        for ip in portScanResult:                        #itterating through the list of ips to write it on differnet lines
            f.write("\n{}".format(ip))
        f.write("\n")
        
    print("\nResults have been logged in ip_port_log.txt, Event Viewer and displayed in the current terminal.\n")