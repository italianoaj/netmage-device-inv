#gets all online ips on the network

import subprocess
import threading
import queue
import re

network = input("Enter the network to scan in CIDR notation: ")
netchunk = network.split("/")
networkID = netchunk[0].rsplit('.',1)[0]
mask = netchunk[1]
ipv4Bits = 32
netbits=int(mask)
hostbits=ipv4Bits-netbits
hosts=(2**hostbits)-2
print("network id is: "+networkID)
print("subnet mask is: "+mask)
print("amount of hosts able to be on this network: "+str(hosts))

def ping(ip_address, presults_queue, nresults_queue, live_ips):
    """Pings a single IP address and puts the result in the queue."""
    try:
        output = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip_address], 
                                         stderr=subprocess.STDOUT,  # Capture stderr as well
                                         timeout=2) # Add timeout to prevent indefinite hanging
        presults_queue.put(f"Host {ip_address} is reachable.\n{output.decode()}")
        live_ips.append(ip_address)
    except subprocess.TimeoutExpired:
        nresults_queue.put(f"Host {ip_address} timed out.")
    except subprocess.CalledProcessError as e:
        nresults_queue.put(f"Host {ip_address} is unreachable. Error: {e}")
    except Exception as e:
        nresults_queue.put(f"Error pinging {ip_address}: {e}")

def ping_threaded(ip_addresses):
    """Pings multiple IP addresses using threads."""
    presults_queue = queue.Queue()
    nresults_queue = queue.Queue()
    threads = []
    online = []
    f = open("offline_ips.log", "a")
    f2 = open("online_ips.log", "a")

    for ip_address in ip_addresses:
        thread = threading.Thread(target=ping, args=(ip_address, presults_queue, nresults_queue, online))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    while not presults_queue.empty():
        f2.write(presults_queue.get())

    while not nresults_queue.empty():
        f.write(nresults_queue.get())

    f.close()
    f2.close()
    return online

def get_mac(ipaddress, ip_mac):
    """uses arp to get the MAC address of a device"""
    """fills an array with IP/MAC address key-pairs"""
    try:
        p1 = subprocess.Popen(["arp", ipaddress], stdout=subprocess.PIPE)
        p2 = subprocess.check_output(['awk', '{print $3}'], stdin=p1.stdout) #get the HW address from arp
        p1.stdout.close() #close p1 output to stop lockout
        dirtyMac=re.search("([0-9a-f]{2}:){5}[0-9a-f]{2}", str(p2)) #regex lookup for mac address
        mac=dirtyMac.group()
        print(mac)
        keyPair = {ipaddress : mac} #make key-pair of mac and ip
        ip_mac.append(keyPair) #add to array
    except Exception as E:
        print(E)

def mac_threaded():
    return


if __name__ == "__main__":
    ip_addresses = []
    macs = []
    for i in range(hosts+1):
        ip_addresses.append(networkID+"."+str(i))
    online = ping_threaded(ip_addresses)
    for ip in online:
        print(ip)
    get_mac(online[2],macs)
    print(macs)
