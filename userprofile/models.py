from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes import generic

import userprofile.signals

# Create your models here.

class Activity(models.Model):
    user = models.ForeignKey(User)
    description = models.CharField(max_length=140)
    timestamp = models.DateTimeField(auto_now_add=True, auto_now=True)

    class Meta:
        ordering = ['-timestamp']

class UserProfile(models.Model):
    user = models.ForeignKey(User, unique=True)
    default_days_back = models.IntegerField(max_length=3, default=7)
    report_frequency = models.IntegerField(max_length=3, default=7)
    show_fp = models.BooleanField("Show False Positives?", default=True)

    report_last_sent = models.DateField(null=True, blank=True)
    comments = generic.GenericRelation('sarim.Comment')

