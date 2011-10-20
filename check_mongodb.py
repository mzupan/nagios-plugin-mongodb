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
#   - @jbraeuer on github
#   - Dag Stockstad <dag.stockstad@gmail.com>
#   - @Andor on github
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
except ImportError, e:
    print e
    sys.exit(2)

def main(argv):
    p = optparse.OptionParser(conflict_handler="resolve", description= "This Nagios plugin checks the health of mongodb.")

    p.add_option('-H', '--host', action='store', type='string', dest='host', default='127.0.0.1', help='The hostname you want to connect to')
    p.add_option('-P', '--port', action='store', type='int', dest='port', default=27017, help='The port mongodb is runnung on')
    p.add_option('-u', '--user', action='store', type='string', dest='user', default=None, help='The username you want to login as')
    p.add_option('-p', '--pass', action='store', type='string', dest='passwd', default=None, help='The password you want to use for that user')
    p.add_option('-W', '--warning', action='store', type='float', dest='warning', default=None, help='The warning threshold we want to set')
    p.add_option('-C', '--critical', action='store', type='float', dest='critical', default=None, help='The critical threshold we want to set')
    p.add_option('-A', '--action', action='store', type='string', dest='action', default='connect', help='The action you want to take')
    p.add_option('-D', '--perf-data', action='store_true', dest='perf_data', default=False, help='Enable output of Nagios performance data')
    p.add_option('-d', '--database', action='store', dest='database', default='admin', help='Specify the database to check')
    options, arguments = p.parse_args()

    host = options.host
    port = options.port
    user = options.user
    passwd = options.passwd
    warning = options.warning
    critical = options.critical
    action = options.action
    perf_data = options.perf_data
    database = options.database

    #
    # moving the login up here and passing in the connection
    #
    start = time.time()
    try:
        con = pymongo.Connection(host, port, slave_okay=True)

        if user and passwd:
            db = con["admin"]
            db.authenticate(user, passwd)
    except Exception, e:
        print e
        sys.exit(2)
    conn_time = time.time() - start
    conn_time = round(conn_time, 0)

    if action == "connections":
        check_connections(con, warning, critical, perf_data)
    elif action == "replication_lag":
        check_rep_lag(con, warning, critical, perf_data)
    elif action == "replset_state":
        check_replset_state(con)
    elif action == "memory":
        check_memory(con, warning, critical, perf_data)
    elif action == "lock":
        check_lock(con, warning, critical, perf_data)
    elif action == "flushing":
        check_flushing(con, warning, critical, True, perf_data)
    elif action == "last_flush_time":
        check_flushing(con, warning, critical, False, perf_data)
    elif action == "index_miss_ratio":
        index_miss_ratio(con, warning, critical, perf_data)
    elif action == "databases":
        check_databases(con, warning, critical)
    elif action == "collections":
        check_collections(con, warning, critical)
    elif action == "database_size":
        check_database_size(con, database, warning, critical, perf_data)
    else:
        check_connect(host, port, warning, critical, perf_data, user, passwd, conn_time)

def exit_with_general_critical(e):
    if isinstance(e, SystemExit):
        sys.exit(e)
    else:
        print "CRITICAL - General MongoDB Error:", e
        sys.exit(2)

def check_connect(host, port, warning, critical, perf_data, user, passwd, conn_time):
    warning = warning or 3
    critical = critical or 6
    message = "Connection took %i seconds" % conn_time
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


def check_connections(con, warning, critical, perf_data):
    warning = warning or 80
    critical = critical or 95
    try:
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
            message += " current_connections=%i" % current
            message += " available_connections=%i" % available
        if used_percent >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif used_percent >= warning:
            print "WARNING - " + message
            sys.exit(1)
        else:
            print "OK - " + message
            sys.exit(0)

    except Exception, e:
        exit_with_general_critical(e)


def check_rep_lag(con, warning, critical, perf_data):
    warning = warning or 600
    critical = critical or 3600
    try:
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

        if lastMasterOpTime is None:
            print "CRITICAL - No active PRIMARY, can't get lag info"
            sys.exit(2)

        data = ""
        lag = 0
        for member in rs_status['members']:
            if member['stateStr'] == 'SECONDARY':
                lastSlaveOpTime = member['optime'].time
                replicationLag = lastMasterOpTime - lastSlaveOpTime - slaveDelays[member['name']]
                
                if replicationLag is None:
                    replicationLag = 0
                    
                data = data + member['name'] + " lag=%s;" % replicationLag
                lag = max(lag, replicationLag)

        data = data[0:len(data)-1]
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

    except Exception, e:
        exit_with_general_critical(e)


def check_memory(con, warning, critical, perf_data):
    #
    # These thresholds are basically meaningless, and must be customized to your system's ram
    #
    warning = warning or 8
    critical = critical or 16
    try:
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
            message += " memory_mapped=%.3fGB" % mem_mapped
            message += " memory_virtual=%.3fGB" % mem_virtual
        if mem_resident >= critical:
            print "CRITICAL - " + message
            sys.exit(2)
        elif mem_resident >= warning:
            print "WARNING - " + message
            sys.exit(1)
        else:
            print "OK - " + message
            sys.exit(0)

    except Exception, e:
        exit_with_general_critical(e)


def check_lock(con, warning, critical, perf_data):
    warning = warning or 10
    critical = critical or 30
    try:
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


    except Exception, e:
        exit_with_general_critical(e)


def check_flushing(con, warning, critical, avg, perf_data):
    #
    # These thresholds mean it's taking 5 seconds to perform a background flush to issue a warning
    # and 10 seconds to issue a critical.
    #
    warning = warning or 5000
    critical = critical or 15000
    try:
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

    except Exception, e:
        exit_with_general_critical(e)


def index_miss_ratio(con, warning, critical, perf_data):
    warning = warning or 10
    critical = critical or 30
    try:
        try:
            data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
        except:
            data = con.admin.command(pymongo.son.SON([('serverStatus', 1)]))

        try:
            miss_ratio = float(data['indexCounters']['btree']['missRatio'])
        except KeyError:
            not_supported_msg = "not supported on this platform"
            if data['indexCounters']['note'] == not_supported_msg:
                print "OK - MongoDB says: " + not_supported_msg
                sys.exit(0)
            else:
                print "WARNING - Can't get counter from MongoDB"
                sys.exit(1)

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

    except Exception, e:
        exit_with_general_critical(e)


def check_replset_state(con):
    try:
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

    except Exception, e:
        exit_with_general_critical(e)

def check_databases(con, warning, critical):
    try:
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

    except Exception, e:
        exit_with_general_critical(e)

def check_collections(con, warning, critical):
    try:
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

    except Exception, e:
        exit_with_general_critical(e)


def check_database_size(con, database, warning, critical, perf_data):
    warning = warning or 100
    critical = critical or 1000
    perfdata = ""
    try:
        data = con[database].command('dbstats')
        storage_size = data['storageSize'] / 1024 / 1024
        if perf_data:
            perfdata += " | database_size=%i;%i;%i" % (storage_size, warning, critical)
            perfdata += " database=%s" %(database)

        if storage_size >= critical:
            print "CRITICAL - Database size: %.0f MB, Database: %s%s" % (storage_size, database, perfdata)
            sys.exit(2)
        elif storage_size >= warning:
            print "WARNING - Database size: %.0f MB, Database: %s%s" % (storage_size, database, perfdata)
            sys.exit(1)
        else:
            print "OK - Database size: %.0f MB, Database: %s%s" % (storage_size, database, perfdata)
            sys.exit(0)
    except Exception, e:
        exit_with_general_critical(e)


#
# main app
#
if __name__ == "__main__":
    main(sys.argv[1:])
