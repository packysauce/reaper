from django.db import models
from django.contrib.contenttypes import generic
from utils.fields import SparseField
from sarim.models import Comment

# Create your models here.
class Plugin(models.Model):
    def __unicode__(self):
        return u'nessus plugin {0}'.format(self.nessusid)
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
    entered = models.DateTimeField(auto_now_add=True)
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        managed = False
        ordering = ['-entered']
        db_table = u'plugin'
        get_latest_by = u'entered'

class PluginDump(models.Model):
    id = models.IntegerField(primary_key=True)
    plugincount = models.IntegerField()
    pluginsadded = models.IntegerField(null=True, blank=True)
    pluginlist = SparseField(blank=True)
    digest = models.CharField(unique=True, max_length=120)
    source = models.ForeignKey('sarim.Source', db_column='sourceid')
    starttime = models.DateTimeField()
    endtime = models.DateTimeField(null=True, blank=True)
    plugins = models.ManyToManyField('Plugin', through='PluginDumpPlugin')
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        managed = False
        db_table = u'plugindump'

class PluginDumpPlugin(models.Model):
    plugindump = models.ForeignKey('PluginDump', db_column='plugindumpid', primary_key=True)
    plugin = models.ForeignKey('Plugin', db_column='pluginid')
    class Meta:
        managed = False
        db_table = u'plugindumpplugin'
