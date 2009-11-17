from django import forms
from django.forms.models import BaseFormSet
from subscriptions.models import *

class SubscriptionForm(forms.ModelForm):
    subscribe_to = forms.CharField(label='Hostname, IP, or VLAN ID (use vXXX)')
    vulns = forms.BooleanField(label='Vulnerabilities')
    comments = forms.BooleanField()
    sod_notify = forms.BooleanField(label='User-initiated scans')
    subscriptions = forms.BooleanField()

    class Meta:
        model = Subscription
        fields = ['subscribe_to', 'vulns','comments','sod_notify','subscriptions']

class SubscriptionFormSet(BaseFormSet):
    def __init__(self, *args, **kwargs):
        self.queryset = self.user.subscriptions.all()
        super(BaseAuthorFormSet, self).__init__(*args, **kwargs)

def subscription_class_factory(user):
    return type('SubscriptionFormSetBase', (SubscriptionFormSet,), {'user': user})
