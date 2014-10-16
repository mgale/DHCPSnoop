#!/usr/bin/env python
#
# Copyright 2011
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Web sites that provided helpful hints and info:
# http://trac.secdev.org/scapy/wiki/DhcpTakeover
# http://www.attackvector.org/network-discovery-via-dhcp-using-python-scapy/
#

import os
import sys
import errno
import ConfigParser
import getopt
from scapy.all import *
import threading

SCRIPT_NAME = os.path.basename(__file__)

version = "1.0git"
version_info = (1,0,0)

# Global main configuration object
MCONFIG = None
LOG = None
DHCP_REPLIES = []

class CaptureThread(threading.Thread):
    """
    Thread to sniff the network packets, sniff is a
    blocking call
    """
    def __init__(self, data_callback, pktcount=5, pkttimeout=5):
        threading.Thread.__init__(self)
        self.pktcount = int(pktcount)
        self.pkttimeout = int(pkttimeout)
        self.data_callback = data_callback
        self.data = None

    def run(self):
        """
        Capture DHCP packets on the network
        """

        sniff(filter="port 67", timeout=self.pkttimeout, 
                count=self.pktcount, prn=self.data_callback, store=0)

    def get_results(self):
        """
        Return results
        """
        return self.data

# should maintain a list of objects, that have information on returned results
# all returned packets should be turned into objects
# each object should contain a good / bad flag
# sha hash to remove duplicate objects

class DHCPResponse(object):
    """
    An object to hold information about a response
    """

    def __init__(self):
        self.opts = {}
        self.isgood = False

    def setIsGood(self):
        self.isgood = True

    def getIsGood(self):
        return self.isgood

    def setOpt(self, opt, value):
        self.opts[opt] = value

    def getOpt(self, opt):
        if (self.opts.has_key(opt)):
            return self.opts[opt]

    def dumpOpts(self):
        return self.opts.keys()


# usage method
def usage():
    usage = """
USAGE: dhcpsnoop.py

Options:
    -h, --help                  This menu ...
    -d, --debug                 Enable debugging
    -v, --verbose               Enable verbose logging

    -c, --config-file=          Configuration file to use
"""

    return usage


# Parse cmd line options
def parse_cmd_line(argv):
    """
    Parse command line arguments

    argv: Pass in cmd line arguments
    config: Global Config object to update with the configuration
    """

    short_args = "dvhc:"
    long_args = ("debug",
                    "verbose",
                    "help",
                    "config-file",
                    )
    try:
        opts, extra_opts = getopt.getopt(argv[1:], short_args, long_args)
    except getopt.GetoptError, e:
        print "Unrecognized command line option or missing required argument: %s" %(e)
        print usage()
        sys.exit(253)

    cmd_line_option_list = {}

    for opt, val in opts:
        if (opt in ("-h", "--help")):
            print usage()
            sys.exit(0)
        elif (opt in ("-d", "--debug")):
            cmd_line_option_list["DEBUG"] = "true"
        elif (opt in ("-v", "--verbose")):
            cmd_line_option_list["VERBOSE"] = "true"
        elif (opt in ("-c", "--config-file")):
            cmd_line_option_list["CONFIGFILE"] = val

    return cmd_line_option_list

def log_setup(verbose, debug):
    log = logging.getLogger("%s" % (SCRIPT_NAME))
    log_level = logging.INFO
    log_level_console = logging.WARNING

    if verbose == True:
        log_level_console = logging.INFO

    if debug == True:
        log_level_console = logging.DEBUG
        log_level = logging.DEBUG

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    console_log = logging.StreamHandler()
    console_log.setLevel(log_level_console)
    console_log.setFormatter(formatter)

    log.setLevel(log_level)
    log.addHandler(console_log)

    return log

def config_load(options):
    """
    Config_load method used to load the configuration

    It creates and returns a config object.
    """

    config = ConfigParser.ConfigParser()

    if (options and options.has_key("CONFIGFILE")):
        cfgfile = options["CONFIGFILE"]
        if (os.path.isfile(cfgfile)):
            config.read("%s" %(cfgfile))
    else:
        print "Could not determine configuration file"
        sys.exit(1)

    return config

def make_dhcp_request(pktface):
    """
    Send a DHCP request on the network

    @pktface: The network interface to use, "eth0".
    """

    conf.checkIPaddr = False
    fam,hw = get_if_raw_hwaddr(conf.iface)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/
        IP(src="0.0.0.0",dst="255.255.255.255")/
        UDP(sport=68,dport=67)/
        BOOTP(chaddr=hw)/
        DHCP(options=[("message-type","discover")]),count=3, iface=pktface)

def dhcp_callback(pkt):
    """
    Check the DHCP response
    """

    try:
        if pkt[DHCP]:
            dhcpresponse = DHCPResponse() 
            for opt in pkt[DHCP].options:
                if opt == 'end':
                    break
                elif opt == 'pad':
                    break
                dhcpresponse.setOpt(opt[0],opt[1])

            if (dhcpresponse.getOpt("message-type") == 2):
                DHCP_REPLIES.append(dhcpresponse)
    except IndexError:
        pass

def main():

    options = parse_cmd_line(sys.argv)
    MCONFIG = config_load(options=options)
    LOG = log_setup(options['VERBOSE'], options['DEBUG'])

    LOG.info("DHCPSnoop started")
    
    LOG.debug("Starting capture thread")
    pktcap = CaptureThread(dhcp_callback, MCONFIG.get("PKTOPTS","pkttime"),
        MCONFIG.get("PKTOPTS","pktcount"))
    pktcap.start()

    LOG.debug("Making dhcp requests")
    make_dhcp_request(MCONFIG.get("PKTOPTS","pktface"))

    pktcap.join()



    for rply in DHCP_REPLIES:
        for i in range(1,10):
            if (not MCONFIG.has_section("server%s"%(i))):
                break

            total_count = len(MCONFIG.options("server%s"%(i)))
            check_count = 0
            for k,v in MCONFIG.items("server%s"%(i)):
                if (rply.getOpt(k) is not None):
                    if (rply.getOpt(k) == v):
                        check_count+=1
                    else:
                        rply.setOpt(k,"%s <--- BAD !!! Wanted '%s'"%(
                                rply.getOpt(k),v))
            if (total_count == check_count):
                rply.setIsGood()

    for rply in DHCP_REPLIES:
        if (rply.getIsGood() == False):
            print "Found bad DHCP response\n"
            for opt in rply.dumpOpts():
                print "\t%s : %s"%(opt, rply.getOpt(opt))

if (__name__ == '__main__'):
    result = main()
    sys.exit(result)

