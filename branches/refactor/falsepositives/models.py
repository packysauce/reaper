from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes import generic
from sarim.models import Comment

# Create your models here.
class FalsePositive(models.Model):
    def get_receiving_object(self):
        return self.plugin

    user = models.ForeignKey(User)
    date_added = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now_add=True, auto_now=True)
    include_all = models.BooleanField()
    includes = models.ManyToManyField('devices.IpAddress', related_name='included_fp')
    excludes = models.ManyToManyField('devices.IpAddress', related_name='excluded_fp')
    comment = models.TextField()
    active = models.BooleanField()
    plugin = models.ForeignKey('plugins.Plugin')
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        get_latest_by = 'last_modified'
        db_table = 'sarimui_falsepositive'
        verbose_name = 'false positive'
