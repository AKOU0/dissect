import unittest
import time
import socket
import struct
import random
import dissect.protos.dns as vs_dns


longdnspkt  = b'\x0b\xb8\x80\x00\x00\x01\x00\x00\x00\r\x00\x0e\x03www\x06google\x03com\x00\x00\x01\x00\x01\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x14\x01e\x0cgtld-servers\x03net\x00\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01b\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01j\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01m\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01i\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01f\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01a\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01g\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01h\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01l\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01k\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01c\xc0.\xc0\x17\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01d\xc0.\xc0,\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x0c^\x1e\xc0L\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0!\x0e\x1e\xc0L\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x03#\x1d\x00\x00\x00\x00\x00\x00\x00\x02\x000\xc0\\\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc00O\x1e\xc0l\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc07S\x1e\xc0|\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0+\xac\x1e\xc0\x8c\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0#3\x1e\xc0\x9c\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x05\x06\x1e\xc0\x9c\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x03\xa8>\x00\x00\x00\x00\x00\x00\x00\x02\x000\xc0\xac\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0*]\x1e\xc0\xbc\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc06p\x1e\xc0\xcc\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0)\xa2\x1e\xc0\xdc\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc04\xb2\x1e\xc0\xec\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1a\\\x1e'
shortdnspkt = b'\xbb\x01\x80\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\t\x00\x04\xd8:\xd8\xc4'
soadnspkt   = b'\xcf7\x81\x80\x00\x01\x00\x01\x00\x01\x00\x01\x03www\x05yahoo\x03com\x00\x00\x06\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x06\xdc\x00\x11\x08atsv2-fp\x03wg1\x01b\xc0\x10\xc04\x00\x06\x00\x01\x00\x00\x01+\x001\x03yf1\xc0\x10\nhostmaster\tyahoo-inc\xc0\x16Y;%\x8b\x00\x00\x00\x1e\x00\x00\x00\x1e\x00\x01Q\x80\x00\x00\x01,\x00\x00)\x02\x00\x00\x00\x00\x00\x00\x00'
class DnsTest(unittest.TestCase):

    def run_dns_query(self,fqdn='www.yahoo.com',dnsserver='8.8.8.8',qtype=vs_dns.DNS_TYPE_A):
        ques = vs_dns.DnsQuestion(name=fqdn, qtype=qtype, qclass=vs_dns.DNS_CLASS_IN)
        msg = vs_dns.DnsMessage()
        msg.transid = random.randint(0, 65535)
        msg.qdcount = 1
        msg.section.question[0] = ques

        if qtype == vs_dns.DNS_TYPE_SOA:
            msg.flags = vs_dns.DNS_FLAG_RECUR | vs_dns.DNS_FLAG_AD
            msg.arcount = 1
            msg.section.additional[0] = vs_dns.DnsOptResourceRecord()
        try:
            self.pkt = msg.vsEmit()
        except Exception as e:
            print('vsEmit (%s): %s' % (fqdn, e))
            return None

        self.sock = None

        if self.sock == None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)
        self.sock.sendto(self.pkt, (dnsserver, 53))
        self.pkt, self.sockaddr = self.sock.recvfrom(65535)

        return self.pkt

    def test_dnsnamelabel(self):
        label     = 'duckduckgo'
        testlabel = vs_dns.DnsNameLabel(label)
        self.assertEqual(testlabel.label.decode('utf-8'),label) #remember, whatevr goes into vbytes comes out as a byte string
        self.assertEqual(testlabel.length,10)

    def test_dnsquestion(self):
        fqdn = 'www.google.com'
        qtype = vs_dns.DNS_TYPE_A
        ques = vs_dns.DnsQuestion(name=fqdn, qtype=qtype, qclass=vs_dns.DNS_CLASS_IN)
        self.assertEqual(ques.qtype,vs_dns.DNS_TYPE_A)
        self.assertEqual(ques.qclass,vs_dns.DNS_CLASS_IN)
        self.assertEqual(ques.qname.getTypeVal(),vs_dns.DnsName(fqdn).getTypeVal())

    def test_dnsquestionarray(self):
        dnsqarray = vs_dns.DnsQuestionArray(0)
        fqdn0 = 'www.duckduckgo.com'
        qtype0 = vs_dns.DNS_TYPE_A
        ques0 = vs_dns.DnsQuestion(name=fqdn0, qtype=qtype0, qclass=vs_dns.DNS_CLASS_IN)
        dnsqarray.vsAddElement(ques0)

        fqdn1 = 'www.google.com'
        qtype1 = vs_dns.DNS_TYPE_A
        ques1= vs_dns.DnsQuestion(name=fqdn1, qtype=qtype1, qclass=vs_dns.DNS_CLASS_IN)
        dnsqarray.vsAddElement(ques1)

        self.assertEqual(dnsqarray[0],ques0)
        self.assertEqual(dnsqarray[1],ques1)

    def test_dnsname(self):
        fqdn = 'www.google.com'
        t_dnsname = vs_dns.DnsName(fqdn)
        self.assertEqual(t_dnsname.vsEmit(),b'\x03www\x06google\x03com\x00')

    def test_dns_query(self):
        fqdn = 'www.google.com' # only needed if you decide to run a live dns query for some reason
        #self.pkt = self.run_dns_query(fqdn,'8.8.8.8') # if we feel like running a new dns query
        self.pkt = longdnspkt #pull a pre-grabbed DNS packet that is long from a root nameserver

        returnmsg =  vs_dns.DnsMessage()
        returnmsg.vsParse(self.pkt)

        addr  = returnmsg.getIPv4Integers()
        ques  = returnmsg.getQuestionRecords()
        answs = returnmsg.getAnswerRecords()
        auths = returnmsg.getAuthorityRecords()
        adtls = returnmsg.getAdditionalRecords()

        emitted_packet = returnmsg.vsEmit()
        self.assertEqual(emitted_packet,self.pkt)

        self.pkt = shortdnspkt  # pull a pre-grabbed DNS answer packet

        returnmsg = vs_dns.DnsMessage()
        returnmsg.vsParse(self.pkt)

        addr = returnmsg.getIPv4Integers()
        ques = returnmsg.getQuestionRecords()
        answs = returnmsg.getAnswerRecords()
        auths = returnmsg.getAuthorityRecords()
        adtls = returnmsg.getAdditionalRecords()

        emitted_packet = returnmsg.vsEmit()
        self.assertEqual(emitted_packet, self.pkt)

    def test_getDnsNames(self):
        self.pkt = longdnspkt

        returnmsg = vs_dns.DnsMessage()
        returnmsg.vsParse(self.pkt)

        names = returnmsg.getDnsNames()
        names.sort()
        expectednames = [
            'a.gtld-servers.net',
            'b.gtld-servers.net',
            'c.gtld-servers.net',
            'com',
            'd.gtld-servers.net',
            'e.gtld-servers.net',
            'f.gtld-servers.net',
            'g.gtld-servers.net',
            'h.gtld-servers.net',
            'i.gtld-servers.net',
            'j.gtld-servers.net',
            'k.gtld-servers.net',
            'l.gtld-servers.net',
            'm.gtld-servers.net',
            'www.google.com'
        ]
        self.assertEqual(names, expectednames)

    def test_getIPv4Integers(self):
        pkt = longdnspkt
        returnmsg = vs_dns.DnsMessage()
        returnmsg.vsParse(pkt)
        ips = returnmsg.getIPv4Integers()
        ips.sort()
        expectedIPs = [
            503711168,
            504242624,
            506667968,
            508506304,
            508770240,
            509352640,
            509422272,
            509480128,
            510670528,
            513944000,
            514599872,
            514995392
        ]
        self.assertEqual(ips, expectedIPs)

        pkt = shortdnspkt
        returnmsg = vs_dns.DnsMessage()
        returnmsg.vsParse(pkt)
        self.assertEqual(returnmsg.getIPv4Integers(), [3302505176])

    def test_getEmailAddresses(self):
        pkt = soadnspkt
        returnmsg = vs_dns.DnsMessage()
        returnmsg.vsParse(pkt)
        emails = returnmsg.getEmailAddresses()
        self.assertEqual(emails, ['hostmaster@yahoo-inc.com'])
