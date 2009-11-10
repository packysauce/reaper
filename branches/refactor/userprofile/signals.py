from django.db.models.signals import post_save
from django.contrib.auth.models import User
from sarim.models import *
from userprofile.models import Activity

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

post_save.connect(comment_handler, sender='sarim.Comment')
post_save.connect(falsepositive_handler, sender='falsepositives.FalsePositive')
