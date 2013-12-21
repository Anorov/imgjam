#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os, sys
import time

if os.getuid() != 0:
    raise OSError("Must run as root")

from scapy.all import *
from multiprocessing import Process
from imgjam import spoof, server

conf.iface = "wlan0"

def main():
    if len(sys.argv) < 2:
        print "Usage: ./%s [image filename or directory] [timeout: default never]" % sys.argv[0]
        return

    if len(sys.argv) == 3:
        timeout = sys.argv[2]
    else:
        timeout = None
    try:
        Process(target=server.start_server).start()
        time.sleep(0.5)
        spoof.spoof(timeout=timeout) #runs until timeout or Ctrl+C
    except:
        pass

if __name__ == "__main__":
    main()
