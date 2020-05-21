from scapy.all import *
import time
import argparse


class scapy_tools():

    def __init__(self):
        self._dns_server = "8.8.8.8"
        self._snd_port = 53


    def nslookup(self, domain: str):
        '''semulate the nslookup command'''
        dns_pack = Ether () / IP(dst=self._dns_server) / UDP(dport=self._snd_port)\
                / DNS(rd=1,qd=DNSQR(qname=domain))
        answer = srp1(dns_pack,verbose = 0)

        print("{0} IP is: {1}".format(domain, answer["DNS Resource Record"].rdata))


    def ping(self, domain: str):
        '''semulate the ping command'''
        print()
        time_list = []
        icmp_msg = Ether () / IP(dst = domain) / ICMP ()
        
        for i in range(3):

            a = time.time()
            ans = srp1(icmp_msg, verbose =0,timeout =5)
            b = time.time()
            time_list.append(b-a)

            if ans:
                print("replay from {0} || time = {1:.2f}".format(domain,time_list[-1]))
            else:
                print("no connection to {0} || time = {1:.2f}".format(domain,time_list[-1]))

        print("\nmax = {0:.2f} || min = {1:.2f} ||avg = {2:.2f}".format(max(time_list), min(time_list)\
                , sum(time_list) /len(time_list) ))


    def tracert(self, domain: str):
        '''semulate the tracert'''
        i = 1
        while True:
            icmp_msg = Ether() / IP(dst = domain, ttl = i) / ICMP()
            ans = srp1(icmp_msg, verbose = 0, timeout = 5)

            print("{0}: {1}".format(i, ans[IP].src))
            
            if ans[ICMP].type == 0:
                break
            
            i+=1


def get_arguments():
    '''get arguments from commaind line'''
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--ping", dest="ping", help="The IP you like to ping")
    parser.add_argument("-t", "--tracert", dest="tracert", help="The IP/domain you like to tracert")
    parser.add_argument("-n", "--nslookup", dest="nslookup", help="The IP you like to nslookup on")
    options = parser.parse_args()
    if not (options.ping or options.nslookup or options.tracert):
        parser.error("[-] Please specify the target IP ,use --help for more info")
    return options




if __name__ == "__main__":
    options = get_arguments()
    tool = scapy_tools()

    if options.ping:
        tool.ping(options.ping)
    elif options.tracert:
        tool.tracert(options.tracert)
    elif options.nslookup:
        tool.nslookup(options.nslookup)