from django.template import Library
from reaper.utils.bobdb import *
from devices.models import *

register = Library()

@register.filter
def is_hostname(x):
    if isinstance(x, basestring):
        if SARIMUI_IP_RE.match(x):
            return False
        if SARIMUI_MAC_RE.match(x):
            return False
        return True

    if not isinstance(x, Hostname):
        return False

    return True

@register.filter
def to_hostname(x):

    if isinstance(x, int):
        return IpHostname.objects.filter(ip = x).latest().hostname.hostname

    if isinstance(x, IpAddress):
        return IpHostname.objects.filter(ip = x).latest().hostname.hostname

    if isinstance(x, Mac):
        return IpHostname.objects.filter(ip = x.macip_set.latest()).latest().hostname.hostname

    if isinstance(x, Hostname):
        return x.hostname

    if isinstance(x, basestring):
        if SARIMUI_IP_RE.match(x):
            return IpHostname.objects.filter(ip = aton(x)).latest().hostname.hostname
        if SARIMUI_MAC_RE.match(x):
            return IpHostname.objects.filter(ip = MacIp.objects.filter(mac = Mac.objects.get(mac=x)).latest().ip).latest().hostname.hostname
        return x
