from django.db.models.signals import post_save, post_delete
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

def comment_handler(sender, **kwargs):
    comment = kwargs['instance']
    user = comment.user
    print "COMMENT HANDLER: " + comment.comment

    if kwargs['created']:
        msg = "Posted a comment on " + str(comment.object)
    else:
        msg = "Modified a comment on " + str(comment.object)

    Activity.objects.create(user = user, description = msg[:140]).save()

def falsepositive_handler(sender, **kwargs):
    fp = kwargs['instance']
    user = User.objects.get(username = fp.added_by)

    if kwargs['created']:
        msg = "Marked plugin %d as a false positive" % fp.plugin.nessusid
    else:
        msg = "Modified false positive for plugin %d" % fp.plugin.nessusid

    Activity.objects.create(user = user, description = msg[:140]).save()


post_save.connect(default_handler)
post_delete.connect(default_handler)
#post_save.connect(comment_handler, sender='sarim.Comment')
#post_save.connect(falsepositive_handler, sender='falsepositives.FalsePositive')
