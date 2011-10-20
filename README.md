# Nagios-MongoDB

## Overview

This is a simple Nagios check script to monitor your MongoDB server(s). 

## Authors

### Main Author
 Mike Zupan mike -(at)- zcentric.com
### Contributers
 - Frank Brandewiede <brande -(at)- travel-iq.com> <brande -(at)- bfiw.de> <brande -(at)- novolab.de>
 - Sam Perman <sam -(at)- brightcove.com>
 - Shlomo Priymak <shlomoid -(at)- gmail.com>
 - @jhoff909 on github
 - Dag Stockstad <dag.stockstad -(at)- gmail.com>

## Installation

In your Nagios plugins directory run

<pre><code>git clone git://github.com/mzupan/nagios-plugin-mongodb.git</code></pre>

## Usage

### Install in Nagios

Edit your commands.cfg and add the following

<pre><code>
define command {
    command_name    check_mongodb
    command_line    $USER1$/nagios-plugin-mongodb/check_mongodb.py -H $HOSTADDRESS$ -A $ARG1$ -P $ARG2$ -W $ARG3$ -C $ARG4$
}

define command {
    command_name    check_mongodb_database
    command_line    $USER1$/nagios-plugin-mongodb/check_mongodb.py -H $HOSTADDRESS$ -A $ARG1$ -P $ARG2$ -W $ARG3$ -C $ARG4$ -d $ARG5$
}
</code></pre>

Then you can reference it like the following. This is is my services.cfg

#### Check Connection

This will check each host that is listed in the Mongo Servers group. It will issue a warning if the connection to the server takes 2 seconds and a critical error if it takes over 4 seconds

<pre><code>
define service {
    use                 generic-service
    hostgroup_name          Mongo Servers
    service_description     Mongo Connect Check
    check_command           check_mongodb!connect!27017!2!4
}
</code></pre>

#### Check Percentage of Open Connections

This is a test that will check the percentage of free connections left on the Mongo server. In the following example it will send out an warning if the connection pool is 70% used and a critical error if it is 80% used. 

<pre><code>
define service {
    use                 generic-service
    hostgroup_name          Mongo Servers
    service_description     Mongo Free Connections
    check_command           check_mongodb!connections!27017!70!80
}
</code></pre>

#### Check Replication Lag

This is a test that will test the replication lag of Mongo servers. It will send out a warning if the lag is over 15 seconds and a critical error if its over 30 seconds. Please note that this check uses 'optime' from rs.status() which will be behind realtime as heartbeat requests between servers only occur every few seconds. Thus this check may show an apparent lag of < 10 seconds when there really isn't any. Use larger values for reliable monitoring.

<pre><code>
define service {
    use                 generic-service
    hostgroup_name          Mongo Servers
    service_description     Mongo Replication Lag
    check_command           check_mongodb!replication_lag!27017!15!30
}
</code></pre>

#### Check Memory Usage

This is a test that will test the memory usage of Mongo server. In my example my Mongo servers have 32 gigs of memory so I'll trigger a warning if Mongo uses over 20 gigs of ram and a error if Mongo uses over 28 gigs of memory.

<pre><code>
define service {
    use                 generic-service
    hostgroup_name          Mongo Servers
    service_description     Mongo Memory Usage
    check_command           check_mongodb!memory!27017!20!28
}
</code></pre>

#### Check Lock Time Percentage

This is a test that will test the lock time percentage of Mongo server. In my example my Mongo I want to be warned if the lock time is above 5% and get an error if it's above 10%. When you start to have lock time it generally means your db is now overloaded.

<pre><code>
define service {
    use                 generic-service
    hostgroup_name          Mongo Servers
    service_description     Mongo Lock Percentage
    check_command           check_mongodb!lock!27017!5!10
}
</code></pre>

#### Check Average Flush Time

This is a test that will check the average flush time of Mongo server. In my example my Mongo I want to be warned if the average flush time is above 100ms and get an error if it's above 200ms. When you start to get a high average flush time it means your database is write bound.

<pre><code>
define service {
    use                 generic-service
    hostgroup_name          Mongo Servers
    service_description     Mongo Flush Average
    check_command           check_mongodb!flushing!27017!100!200
}
</code></pre>

#### Check Last Flush Time

This is a test that will check the last flush time of Mongo server. In my example my Mongo I want to be warned if the last flush time is above 200ms and get an error if it's above 400ms. When you start to get a high flush time it means your server might be needing faster disk or its time to shard.

<pre><code>
define service {
    use                 generic-service
    hostgroup_name          Mongo Servers
    service_description     Mongo Last Flush Time
    check_command           check_mongodb!last_flush_time!27017!200!400
}
</code></pre>

#### Check status of mongodb replicaset
This is a test that will check the status of nodes within a replicaset. Depending which status it is it sends a waring during status 0, 3 and 5, critical if the status is 4, 6 or 8 and a ok with status 1, 2 and 7.

<pre><code>
define service {
      use                     generic-service
      hostgroup_name          Mongo Servers
      service_description     MongoDB state
      check_command           check_mongodb!replset_state!27017
}
</code></pre>

#### Check status of index miss ratio
This is a test that will check the ratio of index hits to misses. If the ratio is high, you should consider adding indexes. I want to get a warning if the ratio is above .005 and get an error if it's above .01

<pre><code>
define service {
      use                     generic-service
      hostgroup_name          Mongo Servers
      service_description     MongoDB state
      check_command           check_mongodb!index_miss_ratio!27017!.005!.01
}
</code></pre>

#### Check number of databases and number of collections
These tests will count the number of databases and the number of collections. It is usefull e.g. when your application "leaks" databases or collections. Set the warning, critical level to fit your application.

<pre><code>
define service {
      use                     generic-service
      hostgroup_name          Mongo Servers
      service_description     MongoDB Number of databases
      check_command           check_mongodb!databases!27017!300!500
}

define service {
      use                     generic-service
      hostgroup_name          Mongo Servers
      service_description     MongoDB Number of collections
      check_command           check_mongodb!collections!27017!300!500
}
</code></pre>



#### Check size of a database
This will check the size of a database. This is useful for keeping track of growth of a particular database.
Replace your-database with the name of your database
<pre><code>
define service {
      use                     generic-service
      hostgroup_name          Mongo Servers
      service_description     MongoDB Database size your-database
      check_command           check_mongodb_database!database_size!27017!300!500!your-database
}
</code></pre>
