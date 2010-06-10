#!/usr/bin/env python

#
#
#
#

import os
import sys
import getopt
import time

try:
    import pymongo
except:
    print "need to install pymongo"
    sys.exit(2)

def main(argv):
    try:
        if len(argv) == 0:
            usage()
            sys.exit(2)
        
        opts, args = getopt.getopt(argv, "H:P:W:C:A:", ["host=", "port=", "warning=", "critical=", "action="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    
    #
    # defaults
    #
    host = "127.0.0.1"
    port = 27017
    warning = 2
    critical = 5
    action = "connect"
    
    for opt, arg in opts:
        if opt in ("-H", "--host"):
            host = arg
        elif opt in ("-P", "--port"):
            port = int(arg)
        elif opt in ("-W", "--warning"):
            warning = int(arg)
        elif opt in ("-C", "--critical"):
            critical = int(arg)
        elif opt in ("-A", "--action"):
            action = arg
        
    if action == "lag":
        pass
    else:
        do_connect(host, port, warning, critical)

def usage():
    print "usage info will go here"


def do_connect(host, port, warning, critical):
    
    try:
        start = time.time()
        con = pymongo.Connection(host, port, network_timeout=critical)
        
        conn_time = time.time() - start
        conn_time = round(conn_time, 0)

        if conn_time >= warning:
            print "WARNING - Connection took %i seconds" % int(conn_time)
            sys.exit(1)
        elif conn_time >= critical:
            print "CRITICAL - Connection took %i seconds" % int(conn_time)
            sys.exit(2)
            
        print "OK - Connection accepted"
        sys.exit(0)
    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)
    
#
# main app
#
if __name__ == "__main__":
    main(sys.argv[1:])