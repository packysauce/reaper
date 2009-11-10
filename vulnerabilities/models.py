from django.db import models
from django.contrib.contenttypes import generic
from devices.models import IpAddress

# Create your models here.
class ScanResults(models.Model):
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


