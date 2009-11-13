from django.db.models.signals import post_save, post_delete, pre_save
from django.contrib.auth.models import User
from sarim.models import *
from userprofile.models import Activity

def default_handler(sender, **kwargs):
    instance = kwargs['instance']
    if not hasattr(instance, 'get_receiving_object'):
        #can't use this object in this handler, bail
        return

    receiver = instance.get_receiving_object()
    user = instance.user
    if kwargs.has_key('created'):
        if kwargs['created']:
            operation = ('created', 'for')
        else:
            operation = ('modified', 'on')
    else:
        operation = ('deleted', 'from')

    desc = "{action} {ins} {v} {rec}".format(
            action=operation[0],
            ins=instance._meta.verbose_name,
            v=operation[1],
            rec=str(receiver)
            )
    
    Activity.objects.create(user = user, description = desc[:140]).save()

def add_email_handler(sender, **kwargs):
    u = kwargs['instance']
    if not u.email:
        u.email = u.username + '@jlab.org'

post_save.connect(default_handler)
pre_save.connect(add_email_handler, sender=User)
post_delete.connect(default_handler)
