from django.db.models.signals import post_save
from django.contrib.auth.models import User
from sarimui.models import UserProfile

def create_profile_handler(sender, **kwargs):
    if kwargs['created'] == True and kwargs['instance'].is_staff:
        UserProfile(user = kwargs['instance']).save()

post_save.connect(create_profile_handler, sender=User)
