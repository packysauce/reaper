from django.db import models

# Create your models here.
class ScanSet(models.Model):
    id = models.IntegerField(primary_key=True)
    digest = models.CharField(unique=True, max_length=192)
    plugindump = models.ForeignKey('PluginDump', db_column='plugindumpid')
    type = models.CharField(max_length=96)
    pluginlist = models.TextField()
    source = models.ForeignKey('Source', db_column='sourceid')
    entered = models.DateTimeField()
    comments = generic.GenericRelation(Comment)
    class Meta:
        managed = False
        db_table = u'scanset'

class ScanRun(models.Model):
    id = models.IntegerField(primary_key=True)
    start = models.DateTimeField()
    end = models.DateTimeField()
    status = models.CharField(max_length=48)
    scanset = models.ForeignKey('sarim.ScanSet', db_column='scansetid')
    hostset = models.ForeignKey('sarim.HostSet', db_column='hostsetid')
    scanner = models.ForeignKey('sarim.Scanner', db_column='scannerid')
    configfile = models.TextField()
    resultfile = models.TextField()
    comments = generic.GenericRelation(Comment)
    class Meta:
        ordering = ['end']
        managed = False
        db_table = u'scanrun'


