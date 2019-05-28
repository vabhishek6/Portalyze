#!/usr/bin/python2.7
"""
Analyzit is a lightweight port scanning application built with python based on sockets.
This application given the host name can carry out an detailed port scan detect the open ports in the target network.
This application was created for education purposes only.

"""
import time
import socket
import subprocess
import sys


logo = """\

8888888b.                888           888                         
888   Y88b               888           888                         
888    888               888           888                         
888   d88P .d88b. 888d888888888 8888b. 888888  88888888888 .d88b.  
8888888P" d88""88b888P"  888       "88b888888  888   d88P d8P  Y8b 
888       888  888888    888   .d888888888888  888  d88P  88888888 
888       Y88..88P888    Y88b. 888  888888Y88b 888 d88P   Y8b.     
888        "Y88P" 888     "Y888"Y888888888 "Y8888888888888 "Y8888  
                                               888                 
                                          Y8b d88P                 
                                           "Y88P"                  
"""

# Clear the screen
subprocess.call('clear', shell=True)

print(u" \033[94m \033[1m {0} \033[0m ".format(logo)).center(60)
print(u"\033[95m With Great Power Comes Great Responsibility \033[0m ")
print("")

# Ask for input
host_machine = raw_input("\033[93m Enter a remote host to scan: \033[0m")
host_port = raw_input("\033[93m Enter the maximum range of the ports you wish to scan\033[0m \033[1m (ex:1023) \033[0m : ")

def analyzit(target_host=None, maxportrange=None):
    """
     Method to check if the User specified port is open.
    @param target_host: Ip of the host machine
    @param maxportrange: Port number of the host who's status has to be determined.
    """

    # Defaults to 1023 if left blank.
    if maxportrange is None:
        maxportrange = 1023
    
    # Some pretty formating.
    print("")
    print(u"\033[94m*\033[0m" * 60)
    print(u"Scanning remote host \U0001F50C {0} for any open ports \U0001F575".format(target_host)).center(60)
    print(u"\033[94m*\033[0m" * 60)
    print("")

    # Check what time the scan started
    start = time.time()

    try:
        for ports in range(1,int(maxportrange)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((target_host, ports))
            if result == 0:
                print("\033[92m Port {} \033[0m: \033[91m Open \033[0m".format(ports))
            sock.close()

    except KeyboardInterrupt:
        print(u"You pressed Ctrl+C \U0001F631")
        sys.exit()

    except socket.gaierror:
        print(u"Provided host address couldn't be resolved. Exiting Application \U0001F625 \U000026A0")
        sys.exit()

    except socket.error:
        print(u"Couldn't connect to the host machine \U0001F631 \U000026A0")
        sys.exit()

    # Checking the time again
    end = time.time()

    # Calculates the difference of time, to see how long it took to run the script
    elapsed_time =  end - start

    #Again jus some Pretty formating.
    print("")

    if elapsed_time > 60:
        print u'\033[91m Blimey!! that was long \U0001F630, it took \033[93m{0}\033[0m \033[91m seconds \U0000FE0F \033[0m'.format(elapsed_time)
    else:
        print u'\033[94m That was fast \U0001F9B8, it just took \033[93m{0}\033[0m \033[94m seconds \U0001F60E \033[0m'.format(elapsed_time)
    
    #Again jus some Pretty formating.
    print("")


if __name__ == '__main__':
    analyzit(target_host=host_machine, maxportrange=host_port)
