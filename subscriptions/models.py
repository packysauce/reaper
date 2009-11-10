from django.db import models
from django.contrib.contenttypes import generic
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User

class Subscription(models.Model):
    #Simple generic many-to-many to allow users to subscribe to a device
    user = models.ForeignKey(User)
    content_type = models.ForeignKey(ContentType)
    object_id = models.PositiveIntegerField()

    #Now what they subscribe to
    vulns = models.BooleanField(default=True)
    comments = models.BooleanField(default=True)
    #more to come...
