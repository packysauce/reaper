from django.db import models
from django.contrib.contenttypes import generic
from devices.models import IpAddress
from plugins.models import *

# Create your models here.
class ScanResults(models.Model):
    def get_vulns(self):   
        nessusids = [i.split('|')[1] for i in self.vulns.split(',')]
        plugins = []

        for nid in nessusids:
            plugins.append(Plugin.objects.filter(nessusid=nid, entered__lte=self.end)[0])

        return plugins

    def __unicode__(self):
        return "{0}".format(self.id)
    id = models.IntegerField(primary_key=True)
    scanrun = models.ForeignKey('scans.ScanRun', db_column='scanrunid')
    ip = models.ForeignKey('devices.IpAddress', db_column='ip', to_field='ip')
    state = models.CharField(max_length=12)
    start = models.DateTimeField()
    end = models.DateTimeField(null=True, blank=True)
    ports = models.TextField(blank=True)
    vulns = models.TextField(blank=True)
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        ordering = ['-id','-end']
        managed = False
        db_table = u'scanresults'
        get_latest_by = u'end'


