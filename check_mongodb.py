#!/usr/bin/env python

#
# A MongoDB Nagios check script
# 

# Script idea taken from a Tag1 script I found and I modified it a lot
#
# Main Author
#   - Mike Zupan <mike@zcentric.com>
# Contributers
#   - Frank Brandewiede <brande@travel-iq.com> <brande@bfiw.de> <brande@novolab.de>
#   - Sam Perman <sam@brightcove.com>
#   - @shlomoid on github
#   - @jhoff909 on github
#   - @jbraeuer on github
#
# USAGE
#
# See the README.md
#

import os
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
    print "%s -H host -A action -P port -W warning -C critical" % sys.argv[0]
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
    print "        - last_flush_time: instantaneous flushing time in ms"
    print "        - replset_state: State of the node within a replset configuration"
    print "        - index_miss_ratio: Check the index miss ratio on queries"
    print "        - databases: Overall number of databases"
    print "        - collections: Number of collections"
    print "  -P : The port MongoDB is running on (defaults to 27017)"
    print "  -W : The warning threshold we want to set"
    print "  -C : The critical threshold we want to set"
    print
    print

def main(argv):

    if len(argv) == 0:
       usage()
       sys.exit(2)

    p = optparse.OptionParser(conflict_handler="resolve", description= "This Nagios plugin checks the health of mongodb.")

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

    try:
        port = int(port_string)
    except ValueError:
        port = 27017
        
    try:
        warning = float(warning_string)
    except ValueError:
        warning = 2

    try:
        critical = float(critical_string)
    except ValueError:
        critical = 5

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
        check_flushing(host, port, warning, critical, True)
    elif action == "last_flush_time":
        check_flushing(host, port, warning, critical, False)
    elif action == "index_miss_ratio":
        index_miss_ratio(host, port, warning, critical)
    elif action == "databases":
        check_databases(host, port, warning, critical)
    elif action == "collections":
        check_collections(host, port, warning, critical)
    else:
        check_connect(host, port, warning, critical)


def check_connect(host, port, warning, critical):
    try:
        start = time.time()
        con = pymongo.Connection(host, port, slave_okay=True, network_timeout=critical)
        
        conn_time = time.time() - start
        conn_time = round(conn_time, 0)

        if conn_time >= critical:
            print "CRITICAL - Connection took %i seconds" % int(conn_time)
            sys.exit(2)
        elif conn_time >= warning:
            print "WARNING - Connection took %i seconds" % int(conn_time)
            sys.exit(1)
            
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

        left_percent = int(float(current / (available + current)) * 100)

        if left_percent >= critical:
            print "CRITICAL -  %i percent (%i of %i connections) used" % (left_percent, current, current + available)
            sys.exit(2)
        elif left_percent >= warning:
            print "WARNING - %i percent (%i of %i connections) used" % (left_percent, current, current + available)
            sys.exit(1)
        else:
            print "OK - %i percent (%i of %i connections) used" % (left_percent, current, current + available)
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)


def check_rep_lag(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)
        
        isMasterStatus = con.admin.command("ismaster", "1")
        if not isMasterStatus['ismaster']:
            print "OK - This is a slave."
            sys.exit(0)
        
        rs_status = con.admin.command("replSetGetStatus")
        
        slaveDelays={}
        
        try:
            #
            # this query fails if --keyfile is enabled
            #
            rs_conf = con.local.system.replset.find_one()
            
            for member in rs_conf['members']:
                if member.get('slaveDelay') is not None:
                    slaveDelays[member['host']] = member.get('slaveDelay')
                else:
                    slaveDelays[member['host']] = 0
        except:
            for member in rs_status['members']:
                slaveDelays[member['name']] = 0

        for member in rs_status['members']:
            if member['stateStr'] == 'PRIMARY':
                lastMasterOpTime = member['optime'].time

        data = ""
        lag = 0
        for member in rs_status['members']:
            if member['stateStr'] == 'SECONDARY':
                lastSlaveOpTime = member['optime'].time
                replicationLag = lastMasterOpTime - lastSlaveOpTime - slaveDelays[member['name']]
                data = data + member['name'] + " lag=" + str(replicationLag) + "; "
                lag = max(lag, replicationLag)


        data = data[0:len(data)-2]

        if lag >= critical:
            print "CRITICAL - Max replication lag: %i [%s]" % (lag, data)
            sys.exit(2)
        elif lag >= warning:
            print "WARNING - Max replication lag: %i [%s]" % (lag, data)
            sys.exit(1)
        else:
            print "OK - Max replication lag: %i [%s]" % (lag, data)
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
        # calculate percentage
        #  
        lock = float(data['globalLock']['lockTime']) / float(data['globalLock']['totalTime']) * 100
        
        if lock >= critical:
            print "CRITICAL - Lock Percentage: %.2f" % lock
            sys.exit(2)
        elif lock >= warning:
            print "WARNING - Lock Percentage: %.2f" % lock
            sys.exit(1)
        else:
            print "OK - Lock Percentage: %.2f" % lock
            sys.exit(0)
        
 
    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)


def check_flushing(host, port, warning, critical, avg):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))

        if avg:
            flush_time = float(data['backgroundFlushing']['average_ms'])
            stat_type = "Avg"
        else:
            flush_time = float(data['backgroundFlushing']['last_ms'])
            stat_type = "Last"

        if flush_time >= critical:
            print "CRITICAL - %s Flush Time: %.2fms" % (stat_type, flush_time)
            sys.exit(2)
        elif flush_time >= warning:
            print "WARNING - %s Flush Time: %.2fms" % (stat_type, flush_time)
            sys.exit(1)
        else:
            print "OK - %s Flush Time: %.2fms" % (stat_type, flush_time)
            sys.exit(0)


    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)

def index_miss_ratio(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))


        miss_ratio = float(data['indexCounters']['btree']['missRatio'])

        if miss_ratio >= critical:
            print "CRITICAL - Miss Ratio: %.4f" % miss_ratio
            sys.exit(2)
        elif miss_ratio >= warning:
            print "WARNING - Miss Ratio: %.4f" % miss_ratio
            sys.exit(1)
        else:
            print "OK - Miss Ratio: %.4f" % miss_ratio
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
            print "CRITICAL - State: %i (Down)" % state
            sys.exit(2)
        elif state == 4:
            print "CRITICAL - State: %i (Fatal error)" % state
            sys.exit(2)
        elif state == 0:
            print "WARNING - State: %i (Starting up, phase1)" % state
            sys.exit(1)
        elif state == 3:
            print "WARNING - State: %i (Recovering)" % state
            sys.exit(1)
        elif state == 5:
            print "WARNING - State: %i (Starting up, phase2)" % state
            sys.exit(1)
        elif state == 1:
            print "OK - State: %i (Primary)" % state
            sys.exit(0)
        elif state == 2:
            print "OK - State: %i (Secondary)" % state
            sys.exit(0)
        elif state == 7:
            print "OK - State: %i (Arbiter)" % state
            sys.exit(0)
        else:
            print "CRITICAL - State: %i (Unknown state)" % state
            sys.exit(2)
        
 
    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)

def check_databases(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('listDatabases', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('listDatabases', 1)]))

        count = len(data['databases'])

        if count >= critical:
            print "CRITICAL - Number of DBs: %.0f" % count
            sys.exit(2)
        elif count >= warning:
            print "WARNING - Number of DBs: %.0f" % count
            sys.exit(1)
        else:
            print "OK - Number of DBs: %.0f" % count
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)

def check_collections(host, port, warning, critical):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('listDatabases', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('listDatabases', 1)]))

        count = 0
        for db in data['databases']:
            dbname = db['name']
            count += len(con[dbname].collection_names())

        if count >= critical:
            print "CRITICAL - Number of collections: %.0f" % count
            sys.exit(2)
        elif count >= warning:
            print "WARNING - Number of collections: %.0f" % count
            sys.exit(1)
        else:
            print "OK - Number of collections: %.0f" % count
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        print "CRITICAL - Connection to MongoDB failed!"
        sys.exit(2)

#
# main app
#
if __name__ == "__main__":
    main(sys.argv[1:])
