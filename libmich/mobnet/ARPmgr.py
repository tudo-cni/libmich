# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich
# * Version : 0.3.0
# *
# * Copyright © 2013. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# * Created by Fabian Eckermann (fabian.eckermann@tu-dortmund.de) from:
# *--------------------------------------------------------
# * File Name : mobnet/GTPmgr.py
# * Created : 2013-11-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

'''
HOWTO:

1) in order to use this GTP tunnels handler, the following parameters need to be configured:

-> some internal parameters
ARPd.GGSN_ETH_IF = 'eth0', ethernet interface toward external networks (e.g. Internet)
APRd.GGSN_MAC_ADDR = '08:00:00:01:02:03', MAC address of the ethernet interface toward external networks
APRd.GGSN_IP_ADDR = '192.168.1.100', IP address set to the ethernet interface toward external networks
GTPUd.EXT_IF = 'eth0', same as ARPd.GGSN_ETH_IF
GTPUd.GGSN_MAC_ADDR = '08:00:00:01:02:03', same as ARPd.GGSN_MAC_ADDR

-> some external network parameters (toward e.g. Internet)
APRd.SUBNET_PREFIX = '192.168.1', subnet prefix of the LAN to which the ethernet interface to external network is connected
APRd.ROUTER_MAC_ADDR = 'f4:00:00:01:02:03', the LAN router (1st IP hop) MAC address
APRd.ROUTER_IP_ADDR = '192.168.1.1', the LAN router (1st IP hop) IP address

-> some internal network parameters (toward RNC / eNodeB)
GTPUd.INT_IP = '10.1.1.1', IP address exposed on the RAN side
GTPUd.INT_PORT = 2152, GTPU UDP port to be used by RAN equipments

-> some mobiles parameters
APRd.IP_POOL = ('192.168.1.201', '192.168.1.202'), the pool of IP addresses to be used by our set of mobiles
GTPUd.BLACKHOLING = True, False or 'ext', to filter out all the mobile trafic, no trafic at all, or IP packets to external network only
GTPUd.WL_ACTIVE = True or False, to allow specific IP packets to be forwarded to the external network, bypassing the BLACKHOLING directive
GTPUd.WL_PORTS = [('UDP', 53), ('UDP', 123)], to specify to list of IP protocol / port to allow in case WL_ACTIVE is True
GTPUd.DPI = True or False, to store packet statistics (protocol / port / DNS requests, see the class DPI) in GTPUd.stats 

2) To use the GTPUd, you need to be root or have the capability to start raw sockets:

-> launch the demon, and add_mobile() / rem_mobile() to add or remove GTPU tunnel endpoint.
>>> gsn = GTPUd()

-> to start forwarding IP packets between the external interface and the GTP tunnel
if you want to let the GTPUd manage the attribution of TEID_to_rnc (GTPUd.GTP_TEID_EXT = False)
>>> teid_to_rnc = gsn.add_mobile(mobile_IP='192.168.1.201', rnc_IP='10.2.1.1', TEID_from_rnc=0x1)
if you want to manage TEID_to_rnc by yourself and just mush its value to GTPUd (GTPUd.GTP_TEID_EXT = True)
>>> add_mobile(self, mobile_IP='192.168.1.201', rnc_IP='10.1.1.2', TEID_from_rnc=0x1, TEID_to_rnc=0x2)

-> to stop forwading IP packets
>>> gsn.rem_mobile(mobile_IP='192.168.1.201')

-> modules that act on GTPU packets can be added to the GTPUd instance, they must be put in the MOD attribute
An example module TCPSYNACK is provided, it answers to TCP SYN packets sent by the mobile
>>> gsn.MOD.append( TCPSYNACK )

3) That's all !
'''
# filtering exports
__all__ = ['ARPd']

import os
#import signal
from select import select

if os.name != 'nt':
    #from fcntl import ioctl
    from socket import socket, timeout, error, \
        ntohs, htons, inet_aton, inet_ntoa, \
        AF_PACKET, SOCK_RAW, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
else:
    print('[ERR] GTPmgr : you\'re not on *nix system. It\'s not going to work:\n'\
          'You need PF_PACKET socket')

from libmich.formats.IP import *
from .utils import *
#
# debug level
DBG = 1

# for getting all kind of ether packets
ETH_P_ALL = 3

#------------------------------------------------------------------------------#
# ARPd                                                                         #
#------------------------------------------------------------------------------#
# It resolves MAC addresses for requested IP addresses
# and listens for incoming ARP requests to answer them with a given MAC address.
#
# when we handle mobiles' IP interfaces over the Gi GGSN interface:
#
# A] for outgoing packets:
# 1) for any IP outside of our network, e.g. 192.168.1.0/24:
# we will provide the ROUTER_MAC_ADDR directly at the GGSN level
# 2) for local IP address in our subnet:
# we will resolve the MAC address thanks to ARP request / response
#
# B] for incoming packets:
# we must answer the router's or local hosts' ARP requests
# before being able to receive IP packets to be transferred to the mobiles
#
# ARPd is going to:
# maintain the ARP_RESOLV_TABLE
# listen on the ethernet interface for:
# - incoming ARP requests, and answer it for IP from our IP_POOL
# - incoming ARP responses (due to the daemon sending ARP requests)
# - incoming IP packets (thx to promiscous mode) to update the ARP_RESOLV_TABLE
#   with new MAC addresses
# send ARP request when needed to be able then to forward IP packet from mobile
#
class ARPd(object):
    '''
    ARP resolver
    resolve Ethernet / IP address correspondence on behalf of connected UE
    '''
    #
    # verbosity level: list of log types to display when calling 
    # self._log(logtype, msg)
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    #
    # recv() buffer length
    BUFLEN = 2048
    # select() timeout and wait period
    SELECT_TO = 0.1
    SELECT_SLEEP = 0.05
    #
    # all Gi interface parameters
    # Our GGSN ethernet parameters (IF, MAC and IP addresses)
    # (and also the MAC address to be used for any mobiles through our GGSN)
    GGSN_ETH_IF = 'eth0'
    GGSN_MAC_ADDR = '08:00:00:01:02:03'
    GGSN_IP_ADDR = '192.168.1.100'
    #
    # the pool of IP address to be used by our mobiles
    IP_POOL = ('192.168.1.201', '192.168.1.202')
    #
    # network parameters:
    # subnet prefix 
    # WNG: we only handle IPv4 /24 subnet
    SUBNET_PREFIX = '192.168.1'
    # and 1st IP router (MAC and IP addresses)
    # this is to resolve directly any IP outside our subnet
    ROUTER_MAC_ADDR = 'f4:00:00:01:02:03'
    ROUTER_IP_ADDR = '192.168.1.1'
    
    def __init__(self):
        #
        self.GGSN_MAC_BUF = mac_aton(self.GGSN_MAC_ADDR)
        self.GGSN_IP_BUF = inet_aton(self.GGSN_IP_ADDR)
        self.SUBNET_PREFIX = self.SUBNET_PREFIX.split('.')[:3]
        self.ROUTER_MAC_BUF = mac_aton(self.ROUTER_MAC_ADDR)
        self.ROUTER_IP_BUF = inet_aton(self.ROUTER_IP_ADDR)
        #
        # init RAW ethernet socket for ARP
        self.sk_arp = socket(AF_PACKET, SOCK_RAW, ntohs(0x0806))
        self.sk_arp.settimeout(0.1)
        #self.sk_arp.setsockopt(SOL_PACKET, SO_RCVBUF, 0)
        self.sk_arp.bind((self.GGSN_ETH_IF, 0x0806))
        #self.sk_arp.setsockopt(SOL_PACKET, SO_RCVBUF, 2**24)
        #
        # init RAW ethernet socket for IPv4
        self.sk_ip = socket(AF_PACKET, SOCK_RAW, ntohs(0x0800))
        self.sk_ip.settimeout(0.1)
        #self.sk_ip.setsockopt(SOL_PACKET, SO_RCVBUF, 0)
        self.sk_ip.bind((self.GGSN_ETH_IF, 0x0800))
        #self.sk_ip.setsockopt(SOL_PACKET, SO_RCVBUF, 2**24)
        #
        # ARP resolution table
        self.ARP_RESOLV_TABLE = {
            self.ROUTER_IP_ADDR : self.ROUTER_MAC_BUF,
            self.GGSN_IP_ADDR : self.GGSN_MAC_BUF,
            }
        for ip in self.IP_POOL:
            self.ARP_RESOLV_TABLE[ip] = self.GGSN_MAC_BUF
        #
        # interrupt handler
        #def sigint_handler(signum, frame):
        #    if self.DEBUG > 1:
        #        self._log('INF', 'CTRL+C caught')
        #    self.stop()
        #signal.signal(signal.SIGINT, sigint_handler)
        #
        # starting main listening loop in background
        self._listening = True
        self._listener_t = threadit(self.listen)
        self._log('INF', 'ARP resolver started')
        #
        # .resolve(ip) method is available for ARP resolution by GTPUd
    
    def _log(self, logtype='DBG', msg=''):
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        if logtype in self.DEBUG:
            log('[{0}] [ARPd] {1}'.format(logtype, msg))
    
    def stop(self):
        if self._listening:
            self._listening = False
            sleep(self.SELECT_TO * 2)
            try:
                self.sk_arp.close()
                self.sk_ip.close()
            except Exception as err:
                self._log('ERR', 'socket error: {0}'.format(err))
    
    def listen(self):
        # select() until we receive arp or ip packet
        while self._listening:
            r = []
            r = select([self.sk_arp, self.sk_ip], [], [], self.SELECT_TO)[0]
            for sk in r:
                buf = bytes()
                try:
                    buf = sk.recvfrom(self.BUFLEN)[0]
                except Exception as err:
                    self._log('ERR', 'external network error (recvfrom): {0}'\
                              .format(err))
                # dipatch ARP request / IP response
                if sk is self.sk_arp \
                and len(buf) >= 42 and buf[12:14] == '\x08\x06':
                    self._process_arpbuf(buf)
                elif sk is self.sk_ip \
                and len(buf) >= 34 and buf[12:14] == '\x08\x00':
                    self._process_ipbuf(buf)
            # if select() timeouts, take a little rest
            if len(r) == 0:
                sleep(self.SELECT_SLEEP)
        #
        self._log('INF', 'ARP resolver stopped')
    
    def _process_arpbuf(self, buf=bytes()):
        # this is an ARP request or response:
        arpop = ord(buf[21:22])
        # 1) check if it requests for one of our IP
        if arpop == 1:
            ipreq = inet_ntoa(buf[38:42])
            if ipreq in self.IP_POOL:
                # reply to it with our MAC ADDR
                try:
                    self.sk_arp.sendto(
                     '{0}{1}\x08\x06\0\x01\x08\0\x06\x04\0\x02{2}{3}{4}{5}'\
                     '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'.format(
                      buf[6:12], self.GGSN_MAC_BUF, # Ethernet hdr
                      self.GGSN_MAC_BUF, buf[38:42], # ARP sender
                      buf[6:12], buf[28:32]), # ARP target 
                     (self.GGSN_ETH_IF, 0x0806))
                except Exception as err:
                    self._log('ERR', 'external network error (sendto) on ARP '\
                              'response: {0}'.format(err))
                else:
                    self._log('DBG', 'ARP response sent for IP: {0}'.format(
                              ipreq))
        # 2) check if it responses something useful for us
        elif arpop == 2:
            ipres = inet_ntoa(buf[28:32])
            if ipres.split('.')[:3] == self.SUBNET_PREFIX \
            and ipres not in self.ARP_RESOLV_TABLE:
                # WNG: no protection (at all) against ARP cache poisoning
                self.ARP_RESOLV_TABLE[ipres] = buf[22:28]
                self._log('DBG', 'got ARP response for new local IP: {0}'\
                          .format(ipres))
    
    def _process_ipbuf(self, buf=bytes()):
        # this is an IPv4 packet : check if src IP is in our subnet
        ipsrc = inet_ntoa(buf[26:30])
        #
        # if local IP and not alreay resolved, store the Ethernet MAC address
        if ipsrc.split('.')[:3] == self.SUBNET_PREFIX \
        and ipsrc not in self.ARP_RESOLV_TABLE:
            # WNG: no protection (at all) against ARP cache poisoning
            self.ARP_RESOLV_TABLE[ipsrc] = buf[6:12]
            self._log('DBG', 'got MAC address from IPv4 packet for new local '\
                      'IP {0}'.format(ipsrc))
    
    def resolve(self, ip='192.168.1.2'):
        #
        # check if already resolved
        if ip in self.ARP_RESOLV_TABLE:
            return self.ARP_RESOLV_TABLE[ip]
        #
        # else, need to request it live on the Ethernet link
        # response will be handled by .listen()
        elif ip.split('.')[:3]  == self.SUBNET_PREFIX:
            ip_buf = inet_aton
            try:
                self.sk_arp.sendto(
                 '{0}{1}\x08\x06\0\x01\x08\0\x06\x04\0\x01{2}{3}\0\0\0\0\0\0{4}'\
                 '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'.format(
                   self.ROUTER_MAC_BUF, self.GGSN_MAC_BUF, # Ethernet hdr
                   self.GGSN_MAC_BUF, self.GGSN_IP_BUF, # ARP sender
                   inet_aton(ip)), # ARP target
                 (self.GGSN_ETH_IF, 0x0806))
            except Exception as err:
                self._log('ERR', 'external network error (sendto) on ARP '\
                          'request: {0}'.format(err))
            else:
                self._log('DBG', 'ARP request sent for IP {0}'.format(ip))
            cnt = 0
            while ip not in self.ARP_RESOLV_TABLE:
                sleep(self.SELECT_SLEEP)
                cnt += 1
                if cnt >= 3:
                    break
            if cnt < 3:
                return self.ARP_RESOLV_TABLE[ip]
            else:
                return 6*'\xFF' # LAN broadcast, maybe a bit strong !
        else:
            return self.ROUTER_MAC_BUF
