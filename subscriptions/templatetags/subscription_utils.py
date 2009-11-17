from django.template import Library
from reaper.utils.bobdb import *
from devices.models import *

import re
register = Library()

@register.filter
def subscribed_to(user, machine):
    if SARIMUI_IP_RE.match(machine):
        if IpAddress.objects.get(ip=aton(machine)).subscribers.filter(user=user):
            return True
    elif SARIMUI_MAC_RE.match(machine):
        if Mac.objects.get(mac=machine).subscribers.filter(user=user):
            return True
    else:
        if Hostname.objects.get(hostname=machine).subscribers.filter(user=user):
            return True

    return False
