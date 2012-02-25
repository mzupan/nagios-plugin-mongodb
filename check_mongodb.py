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
    import pymongo.son
except ImportError, e:
    print e
    sys.exit(2)

#
# thanks to http://stackoverflow.com/a/1229667/72987
#
def optional_arg(arg_default):
    def func(option,opt_str,value,parser):
        if parser.rargs and not parser.rargs[0].startswith('-'):
            val=parser.rargs[0]
            parser.rargs.pop(0)
        else:
            val=arg_default
        setattr(parser.values,option.dest,val)
    return func

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
    p.add_option('-s', '--ssl', dest='ssl', default=False, action='callback', callback=optional_arg(True), help='Connect using SSL')
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
    ssl = options.ssl

    #
    # moving the login up here and passing in the connection
    #
    start = time.time()
    try:
        #
        # ssl connection for pymongo > 2.1
        # 
        if pymongo.version >= "2.1":
            con = pymongo.Connection(host, port, read_preference=pymongo.ReadPreference.SECONDARY, ssl=ssl)
        else:
            con = pymongo.Connection(host, port, slave_okay=True)

        if user and passwd:
            db = con["admin"]
            db.authenticate(user, passwd)
    except Exception, e:
        if isinstance(e,pymongo.errors.AutoReconnect) and str(e).find(" is an arbiter") != -1:
            # We got a pymongo AutoReconnect exception that tells us we connected to an Arbiter Server
            # This means: Arbiter is reachable and can answer requests/votes - this is all we need to know from an arbiter
            print "OK - State: 7 (Arbiter)"
            sys.exit(0)

        print e
        sys.exit(2)
    conn_time = time.time() - start
    conn_time = round(conn_time, 0)

    if action == "connections":
        check_connections(con, warning, critical, perf_data)
    elif action == "replication_lag":
        check_rep_lag(con, host, warning, critical, perf_data)
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

def set_read_preference(db):
    if pymongo.version >= "2.1":
        db.read_preference = pymongo.ReadPreference.SECONDARY

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
            set_read_preference(con.admin)
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


def check_rep_lag(con, host, warning, critical, perf_data):
    warning = warning or 600
    critical = critical or 3600
    try:
        set_read_preference(con.admin)

        # Get replica set status
        rs_status = con.admin.command("replSetGetStatus")

        # Find the primary and/or the current node
        primary_node = None
        host_node = None
        for member in rs_status["members"]:
            if member["stateStr"] == "PRIMARY":
                primary_node = (member["name"], member["optimeDate"])
            if member["name"].split(":")[0].startswith(host):
                host_node = member

        # Check if we're in the middle of an election and don't have a primary
        if primary_node is None:
            print "WARNING - No primary defined. In an election?"
            sys.exit(1)

        # Check if we failed to find the current host
        if host_node is None:
            print "CRITICAL - Unable to find host '" + host + "' in replica set."
            sys.exit(2)

        # Is the specified host the primary?
        if host_node["stateStr"] == "PRIMARY":
            print "OK - This is the primary."
            sys.exit(0)

        # Find the difference in optime between current node and PRIMARY
        optime_lag = abs(primary_node[1] - host_node["optimeDate"])
        lag = str(optime_lag.seconds)
        if optime_lag.seconds > critical:
            print "CRITICAL - lag is " + lag + " seconds"
            sys.exit(2)
        elif optime_lag.seconds > warning:
            print "WARNING - lag is " + lag + " seconds"
            sys.exit(1)
        else:
            print "OK - lag is " + lag + " seconds"
            sys.exit(0)

    except Exception, e:
        print e
        exit_with_general_critical(e)

def check_memory(con, warning, critical, perf_data):
    #
    # These thresholds are basically meaningless, and must be customized to your system's ram
    #
    warning = warning or 8
    critical = critical or 16
    try:
        try:
            set_read_preference(con.admin)
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
            set_read_preference(con.admin)
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
        message += " | lock_percentage=%.2f" % lock_percentage

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
            set_read_preference(con.admin)
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
            set_read_preference(con.admin)
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
            set_read_preference(con.admin)
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
            set_read_preference(con.admin)
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
            set_read_preference(con.admin)
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
        set_read_preference(con.admin)
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

