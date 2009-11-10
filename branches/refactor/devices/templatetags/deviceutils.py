from django.template import Library
from reaper.utils.bobdb import *
from devices.models import *

register = Library()

@register.filter
def to_hostname(x):
    import re

    if SARIMUI_IP_RE.match(x):
        return IpHostname.objects.filter(ip_id = aton(x)).latest().hostname.hostname
    elif SARIMUI_MAC_RE.match(x):
        return IpHostname.objects.filter(ip_id = MacIp.objects.filter(macid = Mac.objects.get(mac=x)).latest().ip_id).hostname.hostname
    else:
        return x
