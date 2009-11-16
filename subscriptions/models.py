from django.db import models
from django.contrib.contenttypes import generic
from django.contrib.contenttypes.models import ContentType

import subscriptions.signals

class Subscription(models.Model):
    def get_receiving_object(self):
        return self.content_object

    #Simple generic many-to-many to allow users to subscribe to a device
    user = models.ForeignKey('auth.User', related_name='subscriptions')
    content_type = models.ForeignKey(ContentType)
    object_id = models.PositiveIntegerField()
    content_object = generic.GenericForeignKey()

    #Now what they subscribe to
    vulns = models.BooleanField(default=True)
    comments = models.BooleanField(default=True)
    #more to come...

    class Meta:
        unique_together = ('user', 'content_type', 'object_id')
