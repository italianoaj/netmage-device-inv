#gets all online ips on the network

import subprocess
import threading
import queue
import re

network = input("Enter the network to scan in CIDR notation: ")
netchunk = network.split("/") #seperate the network ID from the subnet mask
networkID = netchunk[0].rsplit('.',1)[0]
mask = netchunk[1]
ipv4Bits = 32
netbits=int(mask)
hostbits=ipv4Bits-netbits
hosts=(2**hostbits)-2 #math to calculate possible IP range
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
    f = open("offline_ips.log", "a") #open file for error logs
    f2 = open("online_ips.log", "a") #open file for success logs

    for ip_address in ip_addresses:
        thread = threading.Thread(target=ping, args=(ip_address, presults_queue, nresults_queue, online))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    while not presults_queue.empty():
        f2.write(presults_queue.get()) #write positive logs

    while not nresults_queue.empty():
        f.write(nresults_queue.get()) #write negative logs

    f.close() #close files
    f2.close()

    return online #return successfully pinged IPs

def get_mac(ipaddress, ip_mac):
    """uses arp to get the MAC address of a device"""
    """fills an array with IP/MAC address key-pairs"""
    try:
        p1 = subprocess.Popen(["arp", ipaddress], stdout=subprocess.PIPE)
        p2 = subprocess.check_output(['awk', '{print $3}'], stdin=p1.stdout) #get the HW address from arp
        p1.stdout.close() #close p1 output to stop lockout
        dirtyMac=re.search("([0-9a-f]{2}:){5}[0-9a-f]{2}", str(p2)) #regex lookup for mac address
        mac=dirtyMac.group()
        keyPair = {ipaddress : mac} #make key-pair of mac and ip
        ip_mac.append(keyPair) #add to array
    except Exception as E:
        print("Error:")
        print(E)

def mac_threaded(online_ips):
    """Gets multiple mac addresses from online ips using arp"""
    pos_res = queue.Queue()
    threads = []
    ip_mac = []
    f = open("HWaddresses.log", "a")
    for ip in online_ips: #create threads for each ip address
        thread = threading.Thread(target=get_mac, args=(ip, ip_mac))
        threads.append(thread)
        thread.start()
    for thread in threads: #join threads
        thread.join()
    while not pos_res.empty():
        f.write(pos_res.get())

    return ip_mac #return array of ip-mac objects

def get_hostname(ipaddress):
    """uses nmap to pull the hostname of IP addresses"""
    try:
        p1 = subprocess.Popen(["nmap", "-r", ipaddress], stdout=subprocess.PIPE) #run nmap
        p2 = subprocess.Popen(["grep",  "scan report"], stdin=p1.stdout, stdout=subprocess.PIPE) #grep for scan report
        p1.stdout.close() #close subprocess1
        p3 = subprocess.check_output(["awk", '{print $5}'], stdin=p2.stdout) #awk for the 5th segment
        p2.stdout.close()

        print(str(p3)) #print the result

    except Exception as E:
        print("Error Finding Hostname:")
        print(E)

if __name__ == "__main__":
    ip_addresses = []
    macs = []
    for i in range(hosts+1):
        ip_addresses.append(networkID+"."+str(i))
    online = ping_threaded(ip_addresses)
    for ip in online:
        print(ip)
    macs = mac_threaded(online)
    print(macs)
    get_hostname(online[2])
