#!/usr/bin/env python

#
# A MongoDB Nagios check script
# 
# Script idea taken from a Tag1 script I found and I modified it a lot
#
# Contributers
#   - Mike Zupan <mike@zcentric.com> <mzupan@theopenskyproject.com>
#
#
# USAGE
#
# See the README.md
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
        
    if action == "connections":
        check_connections(host, port, warning, critical)
    elif action == "replication_lag":
        check_rep_lag(host, port, warning, critical)
    else:
        check_connect(host, port, warning, critical)

def usage():
    print 
    print "%s -H host -A action -W warning -C critical" % sys.argv[0]
    print
    print "Below are the following flags you can use"
    print
    print "  -H : The hostname you want to connect to"
    print "  -A : The action you want to take"
    print "        - replication_lag : checks the replication lag"
    print "        - connections : checks the percentage of free connections"
    print "        - connect: can we connect to the mongodb server"
    print "  -W : The warning threshold we want to set"
    print "  -C : The critical threshold we want to set"
    print


def check_connect(host, port, warning, critical):
    try:
        start = time.time()
        con = pymongo.Connection(host, port, slave_okay=True, network_timeout=critical)
        
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

def check_connections(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)
        if float(pymongo.version) > 1.7:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1), ('repl', 1)]))
        else:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1), ('repl', 1)]))
            
        current = float(data['connections']['current'])
        available = float(data['connections']['available'])

        left_percent = int(float(current / available) * 100)

        if left_percent >= critical:
            print "CRITICAL - Percentage used: %i" % left_percent
            sys.exit(2)
        elif left_percent >= warning:
            print "WARNING - Percentage used: %i" % left_percent
            sys.exit(1)
        else:
            print "OK - Percentage used: %i" % left_percent
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)

def check_rep_lag(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)
        
        if float(pymongo.version) > 1.7:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1), ('repl', 2)]))
        else:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1), ('repl', 2)]))
            
        #
        # right now this will work for master/slave and replication pairs. It will have to be 
        # fixed for replication sets when they become final
        #
        lag = int(float(data['repl']['sources'][0]['lagSeconds']))
        
        if lag >= critical:
            print "CRITICAL - Replication lag: %i" % lag
            sys.exit(2)
        elif lag >= warning:
            print "WARNING - Replication lag: %i" % lag
            sys.exit(1)
        else:
            print "OK - Replication lag: %i" % lag
            sys.exit(0)
        
 
    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)
#
# main app
#
if __name__ == "__main__":
    main(sys.argv[1:])