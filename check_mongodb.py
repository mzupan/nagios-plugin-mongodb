#!/usr/bin/env python

#
# A MongoDB Nagios check script
# 
# Script idea taken from Mike Zupans check_mongodb.py. Special thanks to Mike for fixing problems within minutes,
# also for being up all sorts of crazy hours ;-)
#
# Contributer of this fork
#   - Frank Brandewiede <brande@travel-iq.com> <brande@bfiw.de>
#
#
# Last changes (11.10.2010): - changes argument parser and error handling
#                            - added check for replsets
#
#
# USAGE
#
# See the README.md
#

import os
import re
import sys
import getopt
import time
import optparse
import string

try:
    import pymongo
except:
    print "need to install pymongo"
    sys.exit(2)

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
    print "        - memory: checks the resident memory used by mongodb in gigabytes"
    print "        - lock: checks percentage of lock time for the server"
    print "        - flushing: checks the average flush time the server"
    print "        - replset_state: State of the node within a replset configuration"
    print "  -W : The warning threshold we want to set"
    print "  -C : The critical threshold we want to set"
    print
    print

def main(argv):

    if len(argv) == 0:
       usage()
       sys.exit(2)

    p = optparse.OptionParser(conflict_handler="resolve", description=\
                "This Nagios plugin checks the health of mongodb. ")

    p.add_option('-H', '--host', action='store', type='string', dest='host', default='127.0.0.1', help='            -H : The hostname you want to connect to')
    p.add_option('-P', '--port', action='store', type='string', dest='port', default='27017', help='            -P : The port mongodb is runnung on')
    p.add_option('-W', '--warning', action='store', type='string', dest='warning', default='2', help='            -W : The warning threshold we want to set')
    p.add_option('-C', '--critical', action='store', type='string', dest='critical', default='5', help='            -C : The critical threshold we want to set')
    p.add_option('-A', '--action', action='store', type='string', dest='action', default='connect', help='            -A : The action you want to take')
    options, arguments = p.parse_args()

    host = options.host
    port_string = options.port
    warning_string = options.warning
    critical_string = options.critical
    action = options.action

    sregex = re.compile('[a-zA-Z]+')

    sresult = sregex.search(port_string)
    if sresult:
	 port = 27017
    else:
	 port = int(port_string)

    sresult = sregex.search(warning_string)
    if sresult:
	 warning = 2
    else:
	 warning = int(warning_string)

    sresult = sregex.search(critical_string)
    if sresult:
	 critical = 5
    else:
	 critical = int(critical_string)

    if action == "connections":
        check_connections(host, port, warning, critical)
    elif action == "replication_lag":
        check_rep_lag(host, port, warning, critical)
    elif action == "replset_state":
        check_replset_state(host, port)
    elif action == "memory":
        check_memory(host, port, warning, critical)
    elif action == "lock":
        check_lock(host, port, warning, critical)        
    elif action == "flushing":
        check_flushing(host, port, warning, critical)
    else:
        check_connect(host, port, warning, critical)


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
        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1), ('repl', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1), ('repl', 1)]))
            
        current = float(data['connections']['current'])
        available = float(data['connections']['available'])

        left_percent = int(float(current / available) * 100)

        if left_percent >= critical:
            print "CRITICAL -  %i percent \(%i of %i connections\) used" % (left_percent, current, available)
            sys.exit(2)
        elif left_percent >= warning:
            print "WARNING - %i percent \(%i of %i connections\) used" % (left_percent, current, available)
            sys.exit(1)
        else:
            print "OK - %i percent \(%i of %i connections\) used" % (left_percent, current, available)
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)


def check_rep_lag(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)
        
        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1), ('repl', 2)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1), ('repl', 2)]))
            
        #
        # right now this will work for master/slave and replication pairs. It will have to be 
        # fixed for replication sets when they become final
        #
        try:
            lag = int(float(data['repl']['sources'][0]['lagSeconds']))
        except:
            print "Not setup for master/slave."
            sys.exit(1)
        
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

        
def check_memory(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)
        
        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))
        
        #
        # convert to gigs
        #  
        mem = float(data['mem']['resident']) / 1000.0
        
        warning = float(warning)
        critical = float(critical)
        
        if mem >= critical:
            print "CRITICAL - Memory Usage: %f GByte" % mem
            sys.exit(2)
        elif mem >= warning:
            print "WARNING - Memory Usage: %f GByte" % mem
            sys.exit(1)
        else:
            print "OK - Memory Usage: %f GByte" % mem
            sys.exit(0)
        
 
    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)
        

def check_lock(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)
        
        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))
        
        #
        # convert to gigs
        #  
        lock = float(data['globalLock']['lockTime']) / float(data['globalLock']['totalTime'])

        warning = float(warning)
        critical = float(critical)
        
        if lock >= critical:
            print "CRITICAL - Lock Percentage: %s" % ("%.2f" % round(lock,2))
            sys.exit(2)
        elif lock >= warning:
            print "WARNING - Lock Percentage: %s" % ("%.2f" % round(lock,2))
            sys.exit(1)
        else:
            print "OK - Lock Percentage: %s" % ("%.2f" % round(lock,2))
            sys.exit(0)
        
 
    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)


def check_flushing(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))

        avg_flush = float(data['backgroundFlushing']['average_ms'])

        warning = float(warning)
        critical = float(critical)

        if avg_flush >= critical:
            print "CRITICAL - Avg Flush Time: %sms" % ("%.2f" % round(avg_flush,2))
            sys.exit(2)
        elif avg_flush >= warning:
            print "WARNING - Avg Flush Time: %sms" % ("%.2f" % round(avg_flush,2))
            sys.exit(1)
        else:
            print "OK - Avg Flush Time: %sms" % ("%.2f" % round(avg_flush,2))
            sys.exit(0)


    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)


def check_replset_state(host, port):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)
        
        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('replSetGetStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('replSetGetStatus', 1)]))
        
        state = int(data['myState'])
        
        if state == 8:
            print "CRITICAL - State: %i \(Down\)" % state
            sys.exit(2)
        elif state == 4:
            print "CRITICAL - State: %i \(Fatal error\)" % state
            sys.exit(2)
        elif state == 0:
            print "WARNING - State: %i \(Starting up, phase1\)" % state
            sys.exit(1)
        elif state == 3:
            print "WARNING - State: %i \(Recovering\)" % state
            sys.exit(1)
        elif state == 5:
            print "WARNING - State: %i \(Starting up, phase2\)" % state
            sys.exit(1)
        elif state == 1:
            print "OK - State: %i \(Primary\)" % state
            sys.exit(0)
        elif state == 2:
            print "OK - State: %i \(Secondary\)" % state
            sys.exit(0)
        elif state == 7:
            print "OK - State: %i \(Arbiter\)" % state
            sys.exit(0)
        else:
            print "CRITICAL - State: %i \(Unknown state\)" % state
            sys.exit(2)
        
 
    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)



#
# main app
#
if __name__ == "__main__":
    main(sys.argv[1:])
