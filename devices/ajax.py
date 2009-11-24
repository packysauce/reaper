from devices.models import *
import django.utils.simplejson as json
from django.http import *
from django.contrib.auth.decorators import user_passes_test
from django.db import connection as cx

@user_passes_test(lambda u: u.is_staff)
def autocomplete_search_devices(request):
    if not request.GET.has_key('q'):
        return HttpResponse( json.dumps({'failure': 'invalid request'}))

    searchstr = request.GET['q']

    hostnames = Hostname.objects.filter(hostname__icontains=searchstr)
    macs = Mac.objects.filter(mac__icontains=searchstr)

    if request.GET.has_key('limit'):
        hostnames = hostnames[:int(request.GET['limit'])]
        macs = macs[:int(request.GET['limit'])]

    return HttpResponse( '\n'.join([i['hostname'] for i in hostnames.values('hostname')]) + 
            '\n'.join([i['mac'] for i in macs.values('mac')]))
