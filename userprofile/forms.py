from django.forms import ModelForm
from django.forms.models import modelformset_factory
from userprofile.models import *

UserProfileFormset = modelformset_factory(UserProfile, extra=0, fields=('default_days_back',))
class UserProfileForm(ModelForm):
    class Meta:
        fields = ('default_days_back','report_frequency', 'show_fp')
        model = UserProfile
