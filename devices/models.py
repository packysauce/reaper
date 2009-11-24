from django.db import models
from django.contrib.contenttypes import generic
from sarim.models import Comment
from utils.bobdb import *
import ipaddr

# Create your models here.
class Hostname(models.Model):
    def __unicode__(self):
        return unicode(self.hostname)

    id = models.IntegerField(primary_key=True)
    hostname = models.CharField(max_length=384)
    comments = generic.GenericRelation('sarim.Comment')
    subscribers = generic.GenericRelation('subscriptions.Subscription')

    class Meta:
        managed = False
        ordering = ['hostname']
        db_table = u'hostname'

class IpAddress(models.Model):
    def __unicode__(self):
        return ntoa(self.ip)
    ip = models.IntegerField(primary_key=True)
    hostnames = models.ManyToManyField('Hostname', through='IpHostname')
    macs = models.ManyToManyField('Mac', through='MacIp', related_name='ipaddresses')
    comments = generic.GenericRelation('sarim.Comment')
    subscribers = generic.GenericRelation('subscriptions.Subscription')

    class Meta:
        ordering = ['ip']
        db_table = u'sarimui_ipaddress'

class IpHostname(models.Model):
    ip = models.ForeignKey('IpAddress', db_column='ip', primary_key=True)
    hostname = models.ForeignKey('Hostname', db_column='hostnameid', primary_key=True)
    observed = models.DateTimeField(primary_key=True)
    entered = models.DateTimeField(auto_now_add=True)
    source = models.ForeignKey('sarim.Source', db_column='sourceid')
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        ordering = ["ip", "-observed"]
        managed = False
        db_table = u'iphostname'
        get_latest_by = u'observed'

class Mac(models.Model):
    def __unicode__(self):
        return self.mac
    id = models.IntegerField(primary_key=True)
    mac = models.CharField(max_length=51, blank=True)
    source = models.ForeignKey('sarim.Source', db_column='sourceid')
    entered = models.DateTimeField(auto_now_add=True)
    comments = generic.GenericRelation('sarim.Comment')
    subscribers = generic.GenericRelation('subscriptions.Subscription')
    class Meta:
        ordering = ["entered"]
        get_latest_by = "entered"
        managed = False
        db_table = u'mac'

class MacIp(models.Model):
    mac = models.ForeignKey('Mac', db_column='macid', primary_key=True)
    ip = models.ForeignKey('IpAddress', db_column='ip', primary_key=True)
    ip_id = models.IntegerField(db_column = 'ip')
    observed = models.DateTimeField(primary_key=True)
    entered = models.DateTimeField(auto_now_add=True)
    source = models.ForeignKey('sarim.Source', db_column='sourceid')
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        ordering = ["ip","-observed"]
        get_latest_by = "observed"
        managed = False
        db_table = u'macip'

class Vlan(models.Model):
    def get_hosts(self):
        ip_list = [int(i) for i in ipaddr.IPNetwork(self.network).iterhosts()]
        return IpAddress.objects.filter(ip__in = ip_list)

    vlan_id = models.IntegerField(max_length=4)
    entered = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    network = models.CharField(max_length=43) #It's big to support IPv6
    purpose = models.TextField()
    comments = generic.GenericRelation('sarim.Comment')
    subscribers = generic.GenericRelation('subscriptions.Subscription')

    class Meta:
        get_latest_by = 'entered'

class VlanDump(models.Model):
    id = models.IntegerField(primary_key=True)
    digest = models.CharField(max_length=192)
    record = models.TextField()
    entered = models.DateTimeField()
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        managed = False
        db_table = u'vlans'
        get_latest_by = 'entered'

class VlanScanState(models.Model):
    id = models.IntegerField(primary_key=True)
    vlannum = models.IntegerField(unique=True)
    entered = models.DateTimeField()
    ex_top20 = models.CharField(max_length=48)
    ex_deep = models.CharField(max_length=48)
    ex_adhoc = models.CharField(max_length=48)
    changedate = models.DateTimeField()
    contact = models.CharField(max_length=96)
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        managed = False
        db_table = u'vlanscanstate'
