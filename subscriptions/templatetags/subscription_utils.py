from reaper.utils.bobdb import *
from django.template import Library
from devices.models import *

import re
register = Library()
@register.filter
def subscribed_to(user, thing):
    if type(thing) == Vlan:
        if thing.subscribers.filter(user=user):
            return True
    else:
        if SARIMUI_IP_RE.match(thing):
            if IpAddress.objects.get(ip=aton(thing)).subscribers.filter(user=user):
                return True
        elif SARIMUI_MAC_RE.match(thing):
            if Mac.objects.get(mac=thing).subscribers.filter(user=user):
                return True
        else:
            if Hostname.objects.get(hostname=thing).subscribers.filter(user=user):
                return True

    return False
