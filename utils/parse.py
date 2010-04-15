#!/usr/bin/env python

import sys, re
from pprint import pprint as pp
from socket import gethostbyname as name2ip
import ipaddr
import MySQLdb

def getip(x):
    return int(ipaddr.IPAddress(name2ip(x)))

#Check for an existing file
if len(sys.argv) != 2:
    sys.stderr.write('Invalid usage. Please specify filename.\n')
    sys.exit()
    
try:
    f = open(sys.argv[1], 'r')
except Exception, e:
    print e
    sys.exit()

scan_data = {}
scan_data['hosts'] = {}
failed = re.compile('.*\[FAILED\].*')

for line in f:
    parts = line.split('|')

    if parts[0] == 'timestamps':
        code, blank, hostname, event, time, blank = parts
        if not hostname:
            # scan event
            scan_data[event] = time
        else:
            # host event
            if not scan_data['hosts'].has_key(hostname):
                scan_data['hosts'][hostname] = {}
            scan_data['hosts'][hostname][event] = time
        continue

    if parts[0] == 'results':
        if len(parts) == 4:
            # open port result
            code, x, hostname, port = parts
            if not scan_data['hosts'].has_key(hostname):
                print "WARNING: result data for host %s prior to host_start event. Check nbe file."
            else:
                if not scan_data['hosts'][hostname].has_key('open_ports'):
                    scan_data['hosts'][hostname]['open_ports'] = []
                scan_data['hosts'][hostname]['open_ports'].append(port)
            continue
        if len(parts) == 7:
            # plugin-based result
            code, x, hostname, port, plugin, result_type, description = parts
            if not failed.match(description):
                continue
            if not scan_data['hosts'].has_key(hostname):
                print "WARNING: result data for host %s prior to host_start event. Check nbe file."
            else:
                if not scan_data['hosts'][hostname].has_key('plugins'):
                    scan_data['hosts'][hostname]['plugins'] = {}
                if not scan_data['hosts'][hostname]['plugins'].has_key(plugin):
                    scan_data['hosts'][hostname]['plugins'][plugin] = {}
                if not scan_data['hosts'][hostname]['plugins'][plugin].has_key(result_type):
                    scan_data['hosts'][hostname]['plugins'][plugin][result_type] = []
                scan_data['hosts'][hostname]['plugins'][plugin][result_type].append( description.replace('\\n','\n').replace('\\\\',chr(92)) )
            continue

nameipmap = {}
DATABASE_ENGINE = 'mysql'           # 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
DATABASE_NAME = 'sarim'             # Or path to database file if using sqlite3.
DATABASE_USER = 'sarim_rw_jsl8'             # Not used with sqlite3.
DATABASE_PASSWORD = '9WXLSyEMfJe8GaKM'         # Not used with sqlite3.
DATABASE_HOST = 'jsdb'             # Set to empty string for localhost. Not used with sqlite3.

db_conn = MySQLdb.connect(host=DATABASE_HOST, user=DATABASE_USER, passwd=DATABASE_PASSWORD, db=DATABASE_NAME)
cursor = db_conn.cursor()
for host in scan_data['hosts']:
    if not nameipmap.has_key(host):
        nameipmap[host] = getip(host)
    if scan_data['hosts'][host].has_key('plugins'):
        for plugin in scan_data['hosts'][host]['plugins']:
            for type in scan_data['hosts'][host]['plugins'][plugin]:
                for result in scan_data['hosts'][host]['plugins'][plugin][type]:
                    cursor.execute("INSERT INTO `compliance_result` (`ip_address_id`, `plugin_id`, `type`, `description`) VALUES (%s, %s, %s, %s)",( nameipmap[host], int(plugin), type, result))
