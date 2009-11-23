from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes import generic

# Create your models here.

class Activity(models.Model):
    user = models.ForeignKey(User)
    description = models.CharField(max_length=140)
    timestamp = models.DateTimeField(auto_now_add=True, auto_now=True)

    class Meta:
        ordering = ['-timestamp']

class UserProfile(models.Model):
    user = models.ForeignKey(User, unique=True)
    default_days_back = models.IntegerField(max_length=2, default=7)
    comments = generic.GenericRelation('sarim.Comment')

