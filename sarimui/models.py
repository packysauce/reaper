# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#     * Rearrange models' order
#     * Make sure each model has one field with primary_key=True
# Feel free to rename the models, but don't rename db_table values or field names.
#
# Also note: You'll have to insert the output of 'django-admin.py sqlcustom [appname]'
# into your database.

from django.db import models
from reaper.fields import SparseField

class Source(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=96)
    description = models.CharField(max_length=192, blank=True)
    entered = models.DateTimeField()
    class Meta:
        managed = False
        db_table = u'source'

class ConfigList(models.Model):
    id = models.IntegerField(primary_key=True)
    comment = models.TextField()
    digest = models.CharField(max_length=192)
    entered = models.DateTimeField()
    config = models.TextField()
    class Meta:
        managed = False
        db_table = u'configlist'

class Hostname(models.Model):
    id = models.IntegerField(primary_key=True)
    hostname = models.CharField(max_length=384)
    class Meta:
        managed = False
        db_table = u'hostname'

class HostSet(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=96)
    type = models.CharField(max_length=48)
    iplist = SparseField(blank=True)
    digest = models.CharField(max_length=192)
    entered = models.DateTimeField()
    sourceid = models.ForeignKey('Source', db_column='sourceid')
    class Meta:
        managed = False
        db_table = u'hostset'

class ImapLoginList(models.Model):
    id = models.IntegerField(primary_key=True)
    ip = models.IntegerField()
    date = models.DateField()
    username = models.CharField(max_length=96)
    class Meta:
        managed = False
        db_table = u'imaploginlist'

class IpComments(models.Model):
    id = models.IntegerField(primary_key=True)
    ip = models.IntegerField()
    entered = models.DateTimeField()
    content = models.TextField()
    analyst = models.CharField(max_length=96)
    sourceid = models.ForeignKey('Source', db_column='sourceid')
    class Meta:
        managed = False
        db_table = u'ipcomments'

class IpHostname(models.Model):
    ip = models.IntegerField(primary_key=True)
    hostnameid = models.ForeignKey('Hostname', db_column='hostnameid')
    observed = models.DateTimeField(primary_key=True)
    entered = models.DateTimeField()
    sourceid = models.ForeignKey('Source', db_column='sourceid')
    class Meta:
        ordering = ["ip", "observed"]
        managed = False
        db_table = u'iphostname'

class Log(models.Model):
    id = models.IntegerField(primary_key=True)
    process = models.CharField(max_length=192)
    start = models.DateTimeField()
    end = models.DateTimeField()
    comment = models.TextField(blank=True)
    class Meta:
        managed = False
        db_table = u'log'

class Mac(models.Model):
    id = models.IntegerField(primary_key=True)
    mac = models.CharField(max_length=51, blank=True)
    sourceid = models.ForeignKey(Source, db_column='sourceid')
    entered = models.DateTimeField()
    class Meta:
        managed = False
        db_table = u'mac'

class MacIp(models.Model):
    macid = models.ForeignKey('Mac', db_column='macid')
    ip = models.IntegerField(primary_key=True)
    observed = models.DateTimeField(primary_key=True)
    entered = models.DateTimeField()
    sourceid = models.ForeignKey('Source', db_column='sourceid')
    class Meta:
        managed = False
        db_table = u'macip'

class Notes(models.Model):
    id = models.IntegerField(primary_key=True)
    note = models.TextField()
    tags = models.TextField(blank=True)
    uid = models.CharField(max_length=48)
    entered = models.DateTimeField()
    class Meta:
        managed = False
        db_table = u'notes'

class Plugin(models.Model):
    id = models.IntegerField(primary_key=True)
    digest = models.CharField(max_length=192, primary_key=True)
    nessusid = models.IntegerField()
    name = models.TextField()
    version = models.CharField(max_length=96)
    summary = models.TextField()
    family = models.CharField(max_length=192)
    category = models.CharField(max_length=96)
    risk = models.CharField(max_length=384)
    cveid = models.TextField(blank=True)
    bugtraqid = models.TextField(blank=True)
    xref = models.TextField(blank=True)
    top20cves = models.TextField(blank=True)
    description = models.TextField(blank=True)
    configfile = models.TextField(blank=True)
    entered = models.DateTimeField()
    class Meta:
        managed = False
        db_table = u'plugin'

class PluginDump(models.Model):
    id = models.IntegerField(primary_key=True)
    plugincount = models.IntegerField()
    pluginsadded = models.IntegerField(null=True, blank=True)
    pluginlist = SparseField(blank=True)
    digest = models.CharField(unique=True, max_length=120)
    sourceid = models.ForeignKey('Source', db_column='sourceid')
    starttime = models.DateTimeField()
    endtime = models.DateTimeField(null=True, blank=True)
    plugins = models.ManyToManyField('Plugin', through='PluginDumpPlugin')
    class Meta:
        managed = False
        db_table = u'plugindump'

class PluginDumpPlugin(models.Model):
    plugindumpid = models.ForeignKey('PluginDump', db_column='plugindumpid')
    pluginid = models.ForeignKey('Plugin', db_column='pluginid')
    class Meta:
        managed = False
        db_table = u'plugindumpplugin'

class Scanner(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=384)
    ip = models.IntegerField()
    entered = models.DateTimeField()
    class Meta:
        managed = False
        db_table = u'scanner'

class ScanResults(models.Model):
    id = models.IntegerField(primary_key=True)
    scanrunid = models.ForeignKey('ScanRun', db_column='scanrunid')
    ip = models.IntegerField()
    state = models.CharField(max_length=12)
    start = models.DateTimeField()
    end = models.DateTimeField(null=True, blank=True)
    ports = models.TextField(blank=True)
    vulns = models.TextField(blank=True)
    class Meta:
        managed = False
        db_table = u'scanresults'

class ScanRun(models.Model):
    id = models.IntegerField(primary_key=True)
    start = models.DateTimeField()
    end = models.DateTimeField()
    status = models.CharField(max_length=48)
    scansetid = models.ForeignKey('ScanSet', db_column='scansetid')
    hostsetid = models.ForeignKey('HostSet', db_column='hostsetid')
    scannerid = models.ForeignKey('Scanner', db_column='scannerid')
    configfile = models.TextField()
    resultfile = models.TextField()
    class Meta:
        managed = False
        db_table = u'scanrun'

class ScanSet(models.Model):
    id = models.IntegerField(primary_key=True)
    digest = models.CharField(unique=True, max_length=192)
    plugindumpid = models.ForeignKey('PluginDump', db_column='plugindumpid')
    type = models.CharField(max_length=96)
    pluginlist = SparseField(blank=True)
    sourceid = models.ForeignKey('Source', db_column='sourceid')
    entered = models.DateTimeField()
    class Meta:
        managed = False
        db_table = u'scanset'

class Schedule(models.Model):
    id = models.IntegerField(primary_key=True)
    type = models.CharField(max_length=48)
    frequency = models.IntegerField()
    unit = models.CharField(max_length=24)
    class Meta:
        managed = False
        db_table = u'schedule'

class Top20Lists(models.Model):
    id = models.IntegerField(primary_key=True)
    digest = models.CharField(max_length=192)
    cvelist = models.TextField()
    entered = models.DateTimeField()
    sourceid = models.ForeignKey('Source', db_column='sourceid')
    class Meta:
        managed = False
        db_table = u'top20lists'

class Vlans(models.Model):
    id = models.IntegerField(primary_key=True)
    digest = models.CharField(max_length=192)
    record = models.TextField()
    entered = models.DateTimeField()
    class Meta:
        managed = False
        db_table = u'vlans'

class VlanScanState(models.Model):
    id = models.IntegerField(primary_key=True)
    vlannum = models.IntegerField(unique=True)
    entered = models.DateTimeField()
    ex_top20 = models.CharField(max_length=48)
    ex_deep = models.CharField(max_length=48)
    ex_adhoc = models.CharField(max_length=48)
    changedate = models.DateTimeField()
    contact = models.CharField(max_length=96)
    class Meta:
        managed = False
        db_table = u'vlanscanstate'

