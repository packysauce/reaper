from devices.models import *
import django.utils.simplejson as json
from django.http import *
from django.contrib.auth.decorators import login_required
from django.db import connection as cx

#@user_passes_test(lambda u: u.is_staff)
def autocomplete_search_devices(request):
    if not request.GET.has_key('q'):
        return HttpResponseBadRequest( json.dumps({'failure': 'invalid request'}))

    searchstr = request.GET['q']

    hostnames = Hostname.objects.filter(hostname__icontains=searchstr)
 
    if request.GET.has_key('limit'):
        hostnames = hostnames[:request.GET['limit']]
    
    print cx.queries[-1]['time']
    print cx.queries[-1]['sql']
    return HttpResponse( '\n'.join([i['hostname'] for i in hostnames.values('hostname')]) )
