# Nagios-MongoDB

## Overview

This is a simple Nagios check script to monitor your MongoDB server(s). 

## Installation

In your Nagios plugins directory run

<pre><code>git clone git://github.com/mzupan/nagios-plugin-mongodb.git</code></pre>

## Usage

### Install in Nagios

Edit your commands.cfg and add the following

<pre><code>
define command {
    command_name    check_mongodb
    command_line    $USER1$/nagios-plugin-mongodb/check_mongodb.py -H $HOSTADDRESS$ -A $ARG1$ -W $ARG2$ -C $ARG3$
}
</code></pre>

Then you can reference it like the following. This is is my services.cfg

#### Check Connection

#### Check Percentage of Open Connections

#### Check Replication Lag



