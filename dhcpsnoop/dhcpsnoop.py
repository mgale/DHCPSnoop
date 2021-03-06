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
import ConfigParser
import getopt
from scapy.all import *
import threading
import logging
import time

SCRIPT_NAME = os.path.basename(__file__)

version = "1.4git"
version_info = (1, 4, 0)

# Global main configuration object
MCONFIG = None
LOG = None
DHCP_REPLIES = []
# Should maintain a list of objects, that have information on returned results
# all returned packets should be turned into a DHCPResponse object
# each object should contain a good / bad flag
# sha hash to remove duplicate objects

class CaptureThread(threading.Thread):
    """
    Thread to sniff the network packets, sniff is a
    blocking call.
    """
    def __init__(self, data_callback, pktcount=5, pkttimeout=5, iface=None):
        threading.Thread.__init__(self)
        self.pktcount = int(pktcount)
        self.pkttimeout = int(pkttimeout)
        self.data_callback = data_callback
        self.iface = iface

    def run(self):
        """
        Capture DHCP packets on the network
        """
        LOG.debug("Sniffing on interface %s" % self.iface)
        sniff(count=self.pktcount,
              filter="port 67 and not host 0.0.0.0",
              iface=self.iface,
              prn=self.data_callback,
              store=0,
              timeout=self.pkttimeout)


class DHCPResponse(object):
    """
    An object to hold information about a response
    """

    def __init__(self):
        self.opts = {}
        self.opt_error = {}
        self.isgood = False
        self.src_mac = None

    def setIsGood(self):
        self.isgood = True

    def getIsGood(self):
        return self.isgood

    def setOpt(self, opt, value):
        self.opts[opt] = value

    def getOpt(self, opt):
        if opt in self.opts:
            return self.opts[opt]

    def dumpOpts(self):
        return self.opts.keys()

    def setOptError(self, opt, error):
        if opt not in self.opt_error:
            self.opt_error[opt] = list()
        self.opt_error[opt].append(error)

    def getOptErrors(self, opt):
        if opt in self.opt_error:
            return self.opt_error[opt]
        else:
            return list()

    def setSrcMac(self, mac):
        self.src_mac = mac

    def getSrcMac(self):
        return self.src_mac


# usage method
def usage():
    usage = """
USAGE: dhcpsnoop.py

Options:
    -h, --help                  This menu ...
    -d, --debug                 Enable debugging
    -v, --verbose               Enable verbose logging

    -c, --config-file=          Configuration file to use
    -i, --interface=            Change the network interface, overriding the configuration file.
"""

    return usage


# Parse cmd line options
def parse_cmd_line(argv):
    """
    Parse command line arguments

    argv: Pass in cmd line arguments
    config: Global Config object to update with the configuration
    """

    short_args = "dvhc:i:"
    long_args = ("debug",
                    "verbose",
                    "help",
                    "config-file",
                    "interface",
                    )
    try:
        opts, extra_opts = getopt.getopt(argv[1:], short_args, long_args)
    except getopt.GetoptError, e:
        print "Unrecognized command line option or missing required argument: %s" %(e)
        print usage()
        sys.exit(253)

    cmd_line_option_list = {}
    cmd_line_option_list['VERBOSE'] = False
    cmd_line_option_list['DEBUG'] = False

    for opt, val in opts:
        if (opt in ("-h", "--help")):
            print usage()
            sys.exit(0)
        elif (opt in ("-d", "--debug")):
            cmd_line_option_list["DEBUG"] = True
        elif (opt in ("-v", "--verbose")):
            cmd_line_option_list["VERBOSE"] = True
        elif (opt in ("-c", "--config-file")):
            cmd_line_option_list["CONFIGFILE"] = val
        elif (opt in ("-i", "--interface")):
            cmd_line_option_list["INTERFACE"] = val

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

    @pktface: The network interface to use, eth0 for example.
    """
    LOG.debug("Making requests on %s" % pktface)
    conf.checkIPaddr = False
    fam,hw = get_if_raw_hwaddr(conf.iface)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/
        IP(src="0.0.0.0",dst="255.255.255.255")/
        UDP(sport=68,dport=67)/
        BOOTP(chaddr=hw)/
        DHCP(options=[("message-type","discover"), "end"]),count=3, iface=pktface)

def dhcp_callback(pkt):
    """
    Handle the DHCP response from the CaptureThread.

    Creates DHCPResponse objects and appends them to the 
    DHCP_REPLIES list.
    """

    LOG.debug("Got a DHCP Response")

    try:
        if pkt[DHCP]:
            dhcpresponse = DHCPResponse()

            LOG.debug("Setting packet src mac : %s" % pkt[Ether].src)
            dhcpresponse.setSrcMac(pkt[Ether].src)

            for opt in pkt[DHCP].options:
                if opt == 'end':
                    break
                elif opt == 'pad':
                    break

                LOG.debug("Setting option: %s : %s" % (opt[0], opt[1]))
                dhcpresponse.setOpt(opt[0],opt[1])

            if (dhcpresponse.getOpt("message-type") == 2):
                DHCP_REPLIES.append(dhcpresponse)
    except IndexError:
        pass

def main():

    global LOG
    exit_code = 0

    options = parse_cmd_line(sys.argv)
    MCONFIG = config_load(options=options)

    if options.has_key("INTERFACE"):
        MCONFIG.set("PKTOPTS", "pktface", options['INTERFACE'])

    LOG = log_setup(options['VERBOSE'], options['DEBUG'])

    LOG.info("DHCPSnoop started")
    LOG.debug("Starting capture thread")
    pktcap = CaptureThread(data_callback=dhcp_callback,
                           pkttimeout=MCONFIG.get("PKTOPTS", "pkttime"),
                           pktcount=MCONFIG.get("PKTOPTS", "pktcount"),
                           iface=MCONFIG.get("PKTOPTS", "pktface"))
    pktcap.start()

    wait_time = 3
    LOG.debug("Waiting %s seconds for capture thread to initialize" % (wait_time))
    time.sleep(wait_time)

    LOG.debug("Making dhcp requests")
    make_dhcp_request(MCONFIG.get("PKTOPTS","pktface"))

    pktcap.join()

    for rply in DHCP_REPLIES:
        for server in [section for section in MCONFIG.sections()
                       if section.startswith('server')]:

            LOG.debug("Checking server: %s" % server)
            # Gets the total number of attributes specified on the
            # configured server in the config file.
            total_checks = len(MCONFIG.options(server))
            checks_completed = 0

            for k, v in MCONFIG.items(server):
                if rply.getOpt(k) is not None:
                    if rply.getOpt(k) == v:
                        checks_completed += 1
                    else:
                        rply.setOptError(
                            k, "\t!!! %s Wanted '%s'" % (server, v))
            if total_checks == checks_completed:
                rply.setIsGood()
                LOG.debug("Configuration Matched: %s" % server)
                break

    for rply in DHCP_REPLIES:
        if rply.getIsGood() is False:
            exit_code += 1
            LOG.critical("Found bad DHCP response from %s" % rply.getSrcMac())
            for opt in rply.dumpOpts():
                error_msgs = rply.getOptErrors(opt)
                if len(error_msgs) > 0:
                    LOG.critical("\t%s : %s <--- BAD" % (opt,
                                                         rply.getOpt(opt)))
                    for error_msg in error_msgs:
                        LOG.critical(error_msg)
                else:
                    LOG.critical("\t%s : %s" % (opt, rply.getOpt(opt)))

    return exit_code


if __name__ == '__main__':
    result = main()
    sys.exit(result)
