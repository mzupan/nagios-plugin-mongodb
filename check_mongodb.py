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
#   - Shlomo Priymak <shlomoid@gmail.com>
#   - @jhoff909 on github
#
# USAGE
#
# See the README.md
#

import sys
import time
import optparse
import textwrap

try:
    import pymongo
except:
    print "Need to install pymongo"
    sys.exit(2)

def usage():
    print "\n %s -H host -A action -P port -W warning -C critical" % sys.argv[0]
    usage_text = """
    Below are the following flags you can use

      -H : The hostname you want to connect to
      -A : The action you want to take
            - replication_lag : checks the replication lag
            - connections : checks the percentage of free connections
            - connect: can we connect to the mongodb server
            - memory: checks the resident memory used by mongodb in gigabytes
            - lock: checks percentage of lock time for the server
            - flushing: checks the average flush time the server
            - last_flush_time: instantaneous flushing time in ms
            - replset_state: State of the node within a replset configuration
            - index_miss_ratio: Check the index miss ratio on queries
      -P : The port MongoDB is running on (defaults to 27017)
      -W : The warning threshold we want to set
      -C : The critical threshold we want to set
      -D : Enable output Nagios performance data (off by default)
    """
    print textwrap.dedent(usage_text)

def main(argv):

    if not len(argv):
        usage()
        sys.exit(2)

    p = optparse.OptionParser(conflict_handler="resolve", description= "This Nagios plugin checks the health of mongodb.")

    p.add_option('-H', '--host', action='store', type='string', dest='host', default='127.0.0.1', help='            -H : The hostname you want to connect to')
    p.add_option('-P', '--port', action='store', type='string', dest='port', default='27017', help='            -P : The port mongodb is runnung on')
    p.add_option('-W', '--warning', action='store', type='string', dest='warning', default='2', help='            -W : The warning threshold we want to set')
    p.add_option('-C', '--critical', action='store', type='string', dest='critical', default='5', help='            -C : The critical threshold we want to set')
    p.add_option('-A', '--action', action='store', type='string', dest='action', default='connect', help='            -A : The action you want to take')
    p.add_option('-D', '--perf-data', action='store_true', dest='perf_data', default=False, help='            -D : Enable output of Nagios performance data')
    options, arguments = p.parse_args()

    host = options.host
    port_string = options.port
    warning_string = options.warning
    critical_string = options.critical
    action = options.action
    perf_data = options.perf_data

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
        check_connections(host, port, warning, critical, perf_data)
    elif action == "replication_lag":
        check_rep_lag(host, port, warning, critical, perf_data)
    elif action == "replset_state":
        check_replset_state(host, port)
    elif action == "memory":
        check_memory(host, port, warning, critical, perf_data)
    elif action == "lock":
        check_lock(host, port, warning, critical, perf_data)
    elif action == "flushing":
        check_flushing(host, port, warning, critical, True, perf_data)
    elif action == "last_flush_time":
        check_flushing(host, port, warning, critical, False, perf_data)
    elif action == "index_miss_ratio":
        index_miss_ratio(host, port, warning, critical, perf_data)
    else:
        check_connect(host, port, warning, critical, perf_data)


def exit_with_connection_critical():
    print "CRITICAL - Connection to MongoDB failed!"
    sys.exit(2)


def check_connect(host, port, warning, critical, perf_data):
    try:
        start = time.time()
        con = pymongo.Connection(host, port, slave_okay=True, network_timeout=critical)

        conn_time = time.time() - start
        conn_time = round(conn_time, 0)

        message = "Connection took %i seconds" % int(conn_time)
        if perf_data:
            message += " | connection_time=%is;%i;%i" % (conn_time, warning, critical)

        if conn_time >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif conn_time >= warning:
            print "WARNING - " + message
            sys.exit(1)

        print "OK - " + message
        sys.exit(0)
    except pymongo.errors.ConnectionFailure:
        exit_with_connection_critical()


def check_connections(host, port, warning, critical, perf_data):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)
        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1), ('repl', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1), ('repl', 1)]))

        current = float(data['connections']['current'])
        available = float(data['connections']['available'])

        used_percent = int(float(current / (available + current)) * 100)
        message = "%i percent (%i of %i connections) used" % (used_percent, current, current + available)
        if perf_data:
            message += " | used_percent=%i%%;%i;%i" % (used_percent, warning, critical)
            message += ",current_connections=%i" % current
            message += ",available_connections=%i" % available
        if used_percent >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif used_percent >= warning:
            print "WARNING - " + message
            sys.exit(1)
        else:
            print "OK - " + message
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        exit_with_connection_critical()


def check_rep_lag(host, port, warning, critical, perf_data):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        isMasterStatus = con.admin.command("ismaster", "1")
        if not isMasterStatus['ismaster']:
            print "OK - This is a slave."
            sys.exit(0)

        rs_status = con.admin.command("replSetGetStatus")

        rs_conf = con.local.system.replset.find_one()

        slaveDelays={}
        for member in rs_conf['members']:
            slaveDelays[member['host']] = member.get('slaveDelay') if member.get('slaveDelay') is not None else 0

        for member in rs_status['members']:
            if member['stateStr'] == 'PRIMARY':
                lastMasterOpTime = member['optime'].time

        if lastMasterOpTime is None:
            print "CRITICAL - No active PRIMARY, can't get lag info"
            sys.exit(2)

        data = ""
        lag = 0
        for member in rs_status['members']:
            if member['stateStr'] == 'SECONDARY':
                lastSlaveOpTime = member['optime'].time
                replicationLag = lastMasterOpTime - lastSlaveOpTime - slaveDelays[member['name']]
                data = data + member['name'] + " lag=%s;" % replicationLag
                lag = max(lag, replicationLag)

        data = data[0:len(data)-2]
        message = "Max replication lag: %i [%s]" % (lag, data)
        if perf_data:
            message += " | max_replication_lag=%is" % lag
        if lag >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif lag >= warning:
            print "WARNING - " + message
            sys.exit(1)
        else:
            print "OK - " + message
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        exit_with_connection_critical()


def check_memory(host, port, warning, critical, perf_data):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))

        if not data['mem']['supported']:
            print "OK - Platform not supported for memory info"
            sys.exit(0)
        #
        # convert to gigs
        #
        mem_resident = float(data['mem']['resident']) / 1024.0
        mem_virtual = float(data['mem']['mapped']) / 1024.0
        mem_mapped = float(data['mem']['virtual']) / 1024.0
        message = "Memory Usage: %.2fGB resident, %.2fGB mapped, %.2fGB virtual" % (mem_resident, mem_mapped, mem_virtual)
        if perf_data:
            message += " | memory_usage=%.3fGB;%.3f;%.3f" % (mem_resident, warning, critical)
            message += ",memory_mapped=%.3fGB" % mem_mapped
            message += ",memory_virtual=%.3fGB" % mem_virtual
        if mem_resident >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif mem_resident >= warning:
            print "WARNING - " + message
            sys.exit(1)
        else:
            print "OK - " + message
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        exit_with_connection_critical()


def check_lock(host, port, warning, critical, perf_data):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))

        #
        # calculate percentage
        #
        lock_percentage = float(data['globalLock']['lockTime']) / float(data['globalLock']['totalTime']) * 100
        message = "Lock Percentage: %.2f%%" % lock_percentage
        if perf_data:
            message += " | lock_percentage=%.2f%%;%i;%i" % (lock_percentage, warning, critical)
            
        if lock_percentage >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif lock_percentage >= warning:
            print "WARNING - " + message
            sys.exit(1)
        else:
            print "OK - " + message
            sys.exit(0)


    except pymongo.errors.ConnectionFailure:
        exit_with_connection_critical()


def check_flushing(host, port, warning, critical, avg, perf_data):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))

        if avg:
            flush_time = float(data['backgroundFlushing']['average_ms'])
            stat_type = "Average"
        else:
            flush_time = float(data['backgroundFlushing']['last_ms'])
            stat_type = "Last"

        message = "%s Flush Time: %.2fms" % (stat_type, flush_time)
        if perf_data:
            message += " | %s_flush_time=%.2fms;%.2f;%.2f" % (stat_type.lower(), flush_time, warning, critical)

        if flush_time >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif flush_time >= warning:
            print "WARNING - " + message
            sys.exit(1)
        else:
            print "OK - " + message
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        exit_with_connection_critical()


def index_miss_ratio(host, port, warning, critical, perf_data):
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))

        miss_ratio = float(data['indexCounters']['btree']['missRatio'])

        message = "Miss Ratio: %.2f" % miss_ratio
        if perf_data:
            message += " | index_miss_ratio=%.2f;%i;%i" % (miss_ratio, warning, critical)
            
        if miss_ratio >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif miss_ratio >= warning:
            print "WARNING - " + message
            sys.exit(1)
        else:
            print "OK - " + message
            sys.exit(0)

    except pymongo.errors.ConnectionFailure:
        exit_with_connection_critical()

        
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
        exit_with_connection_critical()

#
# main app
#
if __name__ == "__main__":
    main(sys.argv[1:])
