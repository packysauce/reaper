from django.db.models.signals import post_save, post_delete
from django.core.mail import send_mail
from django.contrib.auth.models import User
from devices.models import *
from userprofile.models import Activity

def activity_handler(sender, **kwargs):
    instance = kwargs['instance']
    if not hasattr(instance, 'get_receiving_object'):
        #can't use this object in this handler, bail
        return

    receiver = instance.get_receiving_object()
    user = instance.user

    #A user has done something, send all the other users
    #a message indicating what happened
    notify = set([i.user.email for i in receiver.subscribers.all()])
    notify.remove(user.email)
    if len(notify) == 0:
        #nobody's listening...
        return

    send_mail('{user.username} added a {something} to {what}'.format(
        user=user, something =instance._meta.verbose_name, what= str(receiver)),
        ('You are receiving this message because you are subscribed to updates on {what}.\n' +
        '{user.username} has added a {something} to {what}.\n\n\n' +
        'To stop these kinds of notifications, please visit your '+
        'SARIM preferences page and modify your subscription settings').format(
            user=user, something=instance._meta.verbose_name, what=str(receiver)),
        'sarim-notify@jlab.org',
        list(notify)
        )

post_save.connect(activity_handler)
