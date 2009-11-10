# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#     * Rearrange models' order
#     * Make sure each model has one field with primary_key=True
# Feel free to rename the models, but don't rename db_table values or field names.
#
# Also note: You'll have to insert the output of 'django-admin.py sqlcustom [appname]'
# into your database.
import sys
sys.path.append('/opt/reaper')

from django.db import models
from utils.fields import SparseField
from utils.bobdb import *
from django.contrib.contenttypes import generic
from django.contrib.contenttypes.models import ContentType

import django.contrib.auth.models
import sarim.signals

class Comment(models.Model):
    content_type = models.ForeignKey(ContentType)
    object_id = models.PositiveIntegerField()
    object = generic.GenericForeignKey()

    comment = models.TextField()
    #attachment = models.BlobField() ...if we ever get a BlobField this would be nice
    user = models.ForeignKey(django.contrib.auth.models.User)
    entered = models.DateTimeField(auto_now_add = True)
    modified = models.DateTimeField(auto_now_add = True, auto_now = True)

    class Meta:
        ordering = ["modified"]
        db_table = "sarimui_comment"

class Source(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=96)
    description = models.CharField(max_length=192, blank=True)
    entered = models.DateTimeField(auto_now_add = True)
    comments = generic.GenericRelation(Comment)
    class Meta:
        managed = False
        db_table = u'source'

class ConfigList(models.Model):
    id = models.IntegerField(primary_key=True)
    comment = models.TextField()
    digest = models.CharField(max_length=192)
    entered = models.DateTimeField(auto_now_add=True)
    config = models.TextField()
    comments = generic.GenericRelation(Comment)
    class Meta:
        managed = False
        db_table = u'configlist'

class HostSet(models.Model):
    def __unicode__(self):
        return self.name

    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=96)
    type = models.CharField(max_length=48)
    iplist = SparseField(blank=True)
    digest = models.CharField(max_length=192)
    entered = models.DateTimeField(auto_now_add=True)
    source = models.ForeignKey('Source', db_column='sourceid')
    comments = generic.GenericRelation(Comment)
    class Meta:
        managed = False
        db_table = u'hostset'

class Scanner(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=384)
    ip = models.ForeignKey('devices.IpAddress', db_column='ip')
    entered = models.DateTimeField(auto_now_add=True)
    comments = generic.GenericRelation(Comment)
    class Meta:
        managed = False
        db_table = u'scanner'


class Schedule(models.Model):
    id = models.IntegerField(primary_key=True)
    type = models.CharField(max_length=48)
    frequency = models.IntegerField()
    unit = models.CharField(max_length=24)
    comments = generic.GenericRelation(Comment)
    class Meta:
        managed = False
        db_table = u'schedule'

class Top20Lists(models.Model):
    id = models.IntegerField(primary_key=True)
    digest = models.CharField(max_length=192)
    cvelist = models.TextField()
    entered = models.DateTimeField()
    source = models.ForeignKey('Source', db_column='sourceid')
    comments = generic.GenericRelation(Comment)
    class Meta:
        managed = False
        db_table = u'top20lists'



