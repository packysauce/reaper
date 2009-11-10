from django.db.models.signals import post_save
from django.contrib.auth.models import User
from reaper.userprofile.models import UserProfile

def create_profile_handler(sender, **kwargs):
    user_instance = kwargs['instance']
    if user_instance.is_staff == True:
        try:
            user_instance.get_profile()
        except:
            UserProfile(user = user_instance).save()

post_save.connect(create_profile_handler, sender=User)
