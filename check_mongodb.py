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

# As of pymongo v 1.9 the SON API is part of the BSON package, therefore attempt
# to import from there and fall back to pymongo in cases of older pymongo
if pymongo.version >= "1.9":
    import bson.son as son
else:
    import pymongo.son as son

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

def performance_data(perf_data,params):
    data=''
    if perf_data:
        data= " |"
        for p in params:
            p+=(None,None,None,None)
            param,param_name,warning,critical=p[0:4];
            data +=" %s=%s" % (param_name,str(param))    
            if warning or critical:
                warning=warning or 0
                critical=critical or 0
                data+=";%s;%s"%(warning,critical)
    return data

def numeric_type(param):
    if ((type(param)==float or type(param)==int or param==None)):
        return True
    return False
def check_levels(param, warning, critical,message,ok=[]):
    if (numeric_type(critical) and numeric_type(warning)):
        if param >= critical:
            print "CRITICAL - " + message
            return 2
        elif param >= warning:
            print "WARNING - " + message
            return 1
        else:
            print "OK - " + message
            return 0
    else:
        if param in critical:
            print "CRITICAL - " + message
            return 2

        if param in warning:
            print "WARNING - " + message
            return 1

        if param in ok:
            print "OK - " + message
            return 0

        # unexpected param value
        print "CRITICAL - Unexpected value : %d" % param + "; " + message
        return 2

def get_server_status(con):
    try:
        set_read_preference(con.admin)
        data = con.admin.command(pymongo.son_manipulator.SON([('serverStatus', 1)]))
    except:
        data = con.admin.command(son.SON([('serverStatus', 1)]))
    return data

def main(argv):
    p = optparse.OptionParser(conflict_handler="resolve", description= "This Nagios plugin checks the health of mongodb.")

    p.add_option('-H', '--host', action='store', type='string', dest='host', default='127.0.0.1', help='The hostname you want to connect to')
    p.add_option('-P', '--port', action='store', type='int', dest='port', default=27017, help='The port mongodb is runnung on')
    p.add_option('-u', '--user', action='store', type='string', dest='user', default=None, help='The username you want to login as')
    p.add_option('-p', '--pass', action='store', type='string', dest='passwd', default=None, help='The password you want to use for that user')
    p.add_option('-W', '--warning', action='store', dest='warning', default=None, help='The warning threshold we want to set')
    p.add_option('-C', '--critical', action='store', dest='critical', default=None, help='The critical threshold we want to set')
    p.add_option('-A', '--action', action='store', type='choice', dest='action', default='connect', help='The action you want to take',
                 choices=['connect', 'connections', 'replication_lag', 'replset_state', 'memory', 'lock', 'flushing', 'last_flush_time',
                          'index_miss_ratio', 'databases', 'collections', 'database_size','queues','oplog','journal_commits_in_wl'])
    p.add_option('--max-lag',action='store_true',dest='max_lag',default=False,help='Get max replication lag (for replication_lag action only)')
    p.add_option('--mapped-memory',action='store_true',dest='mapped_memory',default=False,help='Get mapped memory instead of resident (if resident memory can not be read)')
    p.add_option('-D', '--perf-data', action='store_true', dest='perf_data', default=False, help='Enable output of Nagios performance data')
    p.add_option('-d', '--database', action='store', dest='database', default='admin', help='Specify the database to check')
    p.add_option('--all-databases', action='store_true', dest='all_databases', default=False, help='Check all databases (action database_size)')
    p.add_option('-s', '--ssl', dest='ssl', default=False, action='callback', callback=optional_arg(True), help='Connect using SSL')
    options, arguments = p.parse_args()

    host = options.host
    port = options.port
    user = options.user
    passwd = options.passwd
    warning = float(options.warning) if (options.warning and options.action!='replset_state') else options.warning 
    critical = float(options.critical) if (options.critical and options.action!='replset_state') else options.critical
    action = options.action
    perf_data = options.perf_data
    max_lag = options.max_lag
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
            return 0
        return exit_with_general_critical(e)            

    conn_time = time.time() - start
    conn_time = round(conn_time, 0)

    if action == "connections":
        return check_connections(con, warning, critical, perf_data)
    elif action == "replication_lag":
        return check_rep_lag(con,  warning, critical, perf_data,max_lag)
    elif action == "replset_state":
        return check_replset_state(con,perf_data, warning , critical )
    elif action == "memory":
        return check_memory(con, warning, critical, perf_data,options.mapped_memory)
    elif action == "queues":
        return check_queues(con, warning, critical, perf_data)
    elif action == "lock":
        return check_lock(con, warning, critical, perf_data)
    elif action == "flushing":
        return check_flushing(con, warning, critical, True, perf_data)
    elif action == "last_flush_time":
        return check_flushing(con, warning, critical, False, perf_data)
    elif action == "index_miss_ratio":
        index_miss_ratio(con, warning, critical, perf_data)
    elif action == "databases":
        return check_databases(con, warning, critical,perf_data)
    elif action == "collections":
        return check_collections(con, warning, critical,perf_data)
    elif action == "oplog":
        return check_oplog(con, warning, critical,perf_data)
    elif action == "journal_commits_in_wl":
        return check_journal_commits_in_wl(con, warning, critical,perf_data)
    elif action == "database_size":
        if options.all_databases:
            return check_all_databases_size(con,warning, critical, perf_data)
        else:
            return check_database_size(con, database, warning, critical, perf_data)
    else:
        return check_connect(host, port, warning, critical, perf_data, user, passwd, conn_time)

def exit_with_general_critical(e):
    if isinstance(e, SystemExit):
        return e
    else:
        print "CRITICAL - General MongoDB Error:", e
    return 2    

def set_read_preference(db):
    if pymongo.version >= "2.1":
        db.read_preference = pymongo.ReadPreference.SECONDARY

def check_connect(host, port, warning, critical, perf_data, user, passwd, conn_time):
    warning = warning or 3
    critical = critical or 6
    message = "Connection took %i seconds" % conn_time
    message += performance_data(perf_data,[(conn_time,"connection_time",warning,critical)])

    return check_levels(conn_time,warning,critical,message)


def check_connections(con, warning, critical, perf_data):
    warning = warning or 80
    critical = critical or 95
    try:
        data=get_server_status(con)

        current = float(data['connections']['current'])
        available = float(data['connections']['available'])

        used_percent = int(float(current / (available + current)) * 100)
        message = "%i percent (%i of %i connections) used" % (used_percent, current, current + available)
        message += performance_data(perf_data,[(used_percent,"used_percent",warning, critical),
                (current,"current_connections"),
                (available,"available_connections")])
        return check_levels(used_percent,warning,critical,message)

    except Exception, e:
        return exit_with_general_critical(e)


def check_rep_lag(con,  warning, critical, perf_data,max_lag):
    warning = warning or 600
    critical = critical or 3600
    rs_status = {}
    slaveDelays={}
    try:
        set_read_preference(con.admin)

        # Get replica set status
        rs_status = con.admin.command("replSetGetStatus")
        rs_conf = con.local.system.replset.find_one()
        for member in rs_conf['members']:
            if member.get('slaveDelay') is not None:
                slaveDelays[member['host']] = member.get('slaveDelay')
            else:
                slaveDelays[member['host']] = 0 
        #print slaveDelays
        # Find the primary and/or the current node
        primary_node = None
        host_node = None
        
        host_status=con.admin.command("ismaster", "1")
        #print "Is master",host_status
        for member in rs_status["members"]:
            if member["stateStr"] == "PRIMARY":
                primary_node = member
            if member["name"]==host_status['me']:
                host_node = member
        #print host_node

        # Check if we're in the middle of an election and don't have a primary
        if primary_node is None:
            print "WARNING - No primary defined. In an election?"
            return 1

        # Check if we failed to find the current host
        # below should never happen
        if host_node is None:
            print "CRITICAL - Unable to find host '" + host + "' in replica set."
            return 2

        # Is the specified host the primary?
        if host_node["stateStr"] == "PRIMARY":
            if max_lag==False:
                print "OK - This is the primary."
                return 0
            else:
                #get the maximal replication lag 
                data=""
                maximal_lag=0
                for member in rs_status['members']:
                    lastSlaveOpTime = member['optimeDate']
                    replicationLag = abs(primary_node["optimeDate"] - lastSlaveOpTime).seconds - slaveDelays[member['name']]
                    data = data + member['name'] + " lag=%d;" % replicationLag
                    maximal_lag = max(maximal_lag, replicationLag)
                message = "Maximal lag is "+str( maximal_lag) + " seconds"
                message +=performance_data(perf_data,[(maximal_lag,"replication_lag",warning, critical)])
                return check_levels(maximal_lag,warning,critical,message) 

        # Find the difference in optime between current node and PRIMARY
        optime_lag = abs(primary_node["optimeDate"] - host_node["optimeDate"])
        lag = optime_lag.seconds
        message = "Lag is "+ str(lag) + " seconds"
        message +=performance_data(perf_data,[(lag,"replication_lag",warning, critical)])
        return check_levels(lag,warning+slaveDelays[host_node['name']],critical+slaveDelays[host_node['name']],message)

    except Exception, e:
        print e
        return exit_with_general_critical(e)

def check_memory(con, warning, critical, perf_data,mapped_memory):
    #
    # These thresholds are basically meaningless, and must be customized to your system's ram
    #
    warning = warning or 8
    critical = critical or 16
    try:
        data=get_server_status(con)
        if not data['mem']['supported'] and not mapped_memory:
            print "OK - Platform not supported for memory info"
            return 0
        #
        # convert to gigs
        #
        message = "Memory Usage:"
        try:
            mem_resident =float(data['mem']['resident']) / 1024.0 
            message += " %.2fGB resident,"%( mem_resident)
        except:
            mem_resident = 0
            message +=" resident unsupported,"
        try:
            mem_virtual = float(data['mem']['virtual']) / 1024.0
            message +=" %.2fGB virtual," % mem_virtual
        except:
            mem_virtual=0
            message +=" virtual unsupported,"
        try:
            mem_mapped = float(data['mem']['mapped']) / 1024.0
            message +=" %.2fGB mapped," % mem_mapped
        except:
            mem_mapped = 0 
            message +=" mapped unsupported,"
        try:
            mem_mapped_journal = float(data['mem']['mappedWithJournal']) / 1024.0
            message +=" %.2fGB mappedWithJournal" % mem_mapped_journal
        except:
            mem_mapped_journal = 0 
        message +=performance_data(perf_data,[("%.2f" % mem_resident,"memory_usage",warning, critical),
                    ("%.2f" % mem_mapped,"memory_mapped"),("%.2f" % mem_virtual,"memory_virtual"),("%.2f" %mem_mapped_journal,"mappedWithJournal")])
        #added for unsupported systems like Solaris
        if mapped_memory and mem_resident==0: 
            return check_levels(mem_mapped,warning,critical,message) 
        else:
            return check_levels(mem_resident,warning,critical,message)

    except Exception, e:
        return exit_with_general_critical(e)


def check_lock(con, warning, critical, perf_data):
    warning = warning or 10
    critical = critical or 30
    try:
        data=get_server_status(con)
        #
        # calculate percentage
        #
        lock_percentage = float(data['globalLock']['lockTime']) / float(data['globalLock']['totalTime']) * 100
        message = "Lock Percentage: %.2f%%" % lock_percentage
        message+=performance_data(perf_data,[("%.2f" % lock_percentage,"lock_percentage",warning,critical)])
        return check_levels(lock_percentage,warning,critical,message)

    except Exception, e:
        return exit_with_general_critical(e)

def check_flushing(con, warning, critical, avg, perf_data):
    #
    # These thresholds mean it's taking 5 seconds to perform a background flush to issue a warning
    # and 10 seconds to issue a critical.
    #
    warning = warning or 5000
    critical = critical or 15000
    try:
        data=get_server_status(con)
        if avg:
            flush_time = float(data['backgroundFlushing']['average_ms'])
            stat_type = "Average"
        else:
            flush_time = float(data['backgroundFlushing']['last_ms'])
            stat_type = "Last"

        message = "%s Flush Time: %.2fms" % (stat_type, flush_time)
        message+=performance_data(perf_data,[("%.2fms" %flush_time,"%s_flush_time" % stat_type.lower(),warning,critical)])

        return check_levels(flush_time,warning,critical,message)

    except Exception, e:
        return exit_with_general_critical(e)

def index_miss_ratio(con, warning, critical, perf_data):
    warning = warning or 10
    critical = critical or 30
    try:
        data=get_server_status(con)

        try:
            miss_ratio = float(data['indexCounters']['btree']['missRatio'])
        except KeyError:
            not_supported_msg = "not supported on this platform"
            if data['indexCounters']['note'] == not_supported_msg:
                print "OK - MongoDB says: " + not_supported_msg
                return 0
            else:
                print "WARNING - Can't get counter from MongoDB"
                return 1

        message = "Miss Ratio: %.2f" % miss_ratio
        message+=performance_data(perf_data,[("%.2f" % miss_ratio,"index_miss_ratio" ,warning,critical)])

        return check_levels(miss_ratio,warning,critical,message)

    except Exception, e:
        return exit_with_general_critical(e)


def check_replset_state(con,perf_data,warning="",critical=""):
    warning = [int(x) for x in warning.split(",")] if warning else [0,3,5]
    critical= [int(x) for x in critical.split(",") ] if critical else [8,4,-1]
    ok = range(-1,8) #should include the range of all posiible values
    try:
        try:
            try:
                set_read_preference(con.admin)
                data = con.admin.command(pymongo.son_manipulator.SON([('replSetGetStatus', 1)]))
            except:
                data = con.admin.command(son.SON([('replSetGetStatus', 1)]))
            state = int(data['myState'])
        except pymongo.errors.OperationFailure,e :
            if e.code==None and e.message.find('failed: not running with --replSet"'):
                state=-1

        if state == 8:
            message="State: %i (Down)" % state
        elif state == 4:
            message="State: %i (Fatal error)" % state
        elif state == 0:
            message="State: %i (Starting up, phase1)" % state
        elif state == 3:
            message="State: %i (Recovering)" % state
        elif state == 5:
            message="State: %i (Starting up, phase2)" % state
        elif state == 1:
            message="State: %i (Primary)" % state
        elif state == 2:
            message="State: %i (Secondary)" % state
        elif state == 7:
            message="State: %i (Arbiter)" % state
        elif state==-1:
            message="Not running with replSet"
        else:
            message="State: %i (Unknown state)" % state
        message+=performance_data(perf_data,[(state,"state")])
        return check_levels(state,warning,critical,message,ok)
    except Exception, e:
        return exit_with_general_critical(e)

def check_databases(con, warning, critical,perf_data=None):
    try:
        try:
            set_read_preference(con.admin)
            data = con.admin.command(pymongo.son_manipulator.SON([('listDatabases', 1)]))
        except:
            data = con.admin.command(son.SON([('listDatabases', 1)]))

        count = len(data['databases'])
        message="Number of DBs: %.0f" % count
        message+=performance_data(perf_data,[(count,"databases",warning,critical,message)])
        return check_levels(count,warning,critical,message)
    except Exception, e:
        return exit_with_general_critical(e)

def check_collections(con, warning, critical,perf_data=None):
    try:
        try:
            set_read_preference(con.admin)
            data = con.admin.command(pymongo.son_manipulator.SON([('listDatabases', 1)]))
        except:
            data = con.admin.command(son.SON([('listDatabases', 1)]))

        count = 0
        for db in data['databases']:
            dbname = db['name']
            count += len(con[dbname].collection_names())

        message="Number of collections: %.0f" % count
        message+=performance_data(perf_data,[(count,"collections",warning,critical,message)])
        return check_levels(count,warning,critical,message)

    except Exception, e:
        return exit_with_general_critical(e)


def check_all_databases_size(con, warning, critical, perf_data):
    warning = warning or 100
    critical = critical or 1000

    try: 
        set_read_preference(con.admin)
        all_dbs_data = con.admin.command(pymongo.son_manipulator.SON([('listDatabases', 1)]))
    except:
        all_dbs_data = con.admin.command(son.SON([('listDatabases', 1)]))
    
    total_storage_size=0
    message=""
    perf_data_param=[()]
    for db in all_dbs_data['databases']:
        database = db['name']
        data = con[database].command('dbstats') 
        storage_size = data['storageSize'] / 1024 / 1024
        message+="; Database %s size: %.0f MB"%(database,storage_size)
        perf_data_param.append((storage_size,database+"_database_size"))
        total_storage_size+=storage_size
    
    perf_data_param[0]=(total_storage_size,"total_size",warning,critical)
    message+=performance_data(perf_data,perf_data_param)
    message="Total size: %.0f MB" % total_storage_size + message
    return check_levels(total_storage_size,warning,critical,message)

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
            return 2
        elif storage_size >= warning:
            print "WARNING - Database size: %.0f MB, Database: %s%s" % (storage_size, database, perfdata)
            return 1
        else:
            print "OK - Database size: %.0f MB, Database: %s%s" % (storage_size, database, perfdata)
            return 0
    except Exception, e:
        return exit_with_general_critical(e)

def check_queues(con, warning, critical, perf_data):
    warning = warning or 10
    critical = critical or 30
    try:
        data=get_server_status(con)

        total_queues = float(data['globalLock']['currentQueue']['total']) 
        readers_queues = float(data['globalLock']['currentQueue']['readers']) 
        writers_queues = float(data['globalLock']['currentQueue']['writers']) 
        message = "Current queue is : total = %d, readers = %d, writers = %d" % (total_queues, readers_queues, writers_queues)
        message+=performance_data(perf_data,[(total_queues, "total_queues",warning,critical),(readers_queues, "readers_queues"),(writers_queues,"writers_queues")])
        return check_levels(total_queues,warning,critical,message)

    except Exception, e:
        return exit_with_general_critical(e)

def check_oplog(con, warning, critical, perf_data):
    """ Checking the oplog time - the time of the log currntly saved in the oplog collection
    defaults:
        critical 4 hours
        warning 24 hours 
    those can be changed as usual with -C and -W parameters"""
    warning = warning or 24 
    critical = critical or 4
    try:
        db = con.local
        ol=db.system.namespaces.find_one({"name":"local.oplog.rs"}) 
        if (db.system.namespaces.find_one({"name":"local.oplog.rs"}) != None) :
            oplog = "oplog.rs";
        else :
            ol=db.system.namespaces.find_one({"name":"local.oplog.$main"})
            if (db.system.namespaces.find_one({"name":"local.oplog.$main"}) != None) :
                oplog = "oplog.$main";
            else :
                message = "neither master/slave nor replica set replication detected";
                return check_levels(None,warning,critical,message)

        try:
                set_read_preference(con.admin)
                data=con.local.command(pymongo.son_manipulator.SON([('collstats',oplog)]))
        except:
                data = con.admin.command(son.SON([('collstats',oplog)]))

        ol_size=data['size']
        ol_storage_size=data['storageSize']
        ol_used_storage=int(float(ol_size)/ol_storage_size*100+1)
        ol=con.local[oplog]
        firstc = ol.find().sort("$natural",pymongo.ASCENDING).limit(1)[0]['ts']
        lastc = ol.find().sort("$natural",pymongo.DESCENDING).limit(1)[0]['ts']
        time_in_oplog= (lastc.as_datetime()-firstc.as_datetime())
        message="Oplog saves "+ str(time_in_oplog) + " %d%% used" %ol_used_storage 
        try: #work starting from python2.7
            hours_in_oplog= time_in_oplog.total_seconds()/60/60
        except:
            hours_in_oplog= float(time_in_oplog.seconds + time_in_oplog.days * 24 * 3600)/60/60
        approx_level=hours_in_oplog*100/ol_used_storage
        message+=performance_data(perf_data,[("%.2f" % hours_in_oplog,'oplog_time',warning,critical),("%.2f " % approx_level, 'oplog_time_100_percent_used')])
        return check_levels(-approx_level,-warning,-critical,message)

    except Exception, e:
        return exit_with_general_critical(e)

def check_journal_commits_in_wl(con, warning, critical,perf_data):
    """  Checking the number of commits which occurred in the db's write lock. 
Most commits are performed outside of this lock; committed while in the write lock is undesirable. 
Under very high write situations it is normal for this value to be nonzero.  """

    warning = warning or 10
    critical = critical or 40
    try:
        data=get_server_status(con)
        j_commits_in_wl = data['dur']['commitsInWriteLock'] 
        message="Journal commits in DB write lock : %d" % j_commits_in_wl
        message+=performance_data(perf_data,[(j_commits_in_wl,"j_commits_in_wl",warning, critical)])
        return check_levels(j_commits_in_wl,warning, critical, message)

    except Exception, e:
        return exit_with_general_critical(e)
    
#
# main app
#
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

