from plugins.models import *
import django.utils.simplejson as json
from django.http import *
from django.contrib.auth.decorators import user_passes_test

import sys
sys.stdout = sys.stderr

@user_passes_test(lambda u: u.is_staff)
def autocomplete_search_plugins(request):
    if not request.GET.has_key('q'):
        return HttpResponse( json.dumps({'failure': 'invalid request'}))

    searchstr = request.GET['q']
    plugins = Plugin.objects.filter(nessusid__contains=searchstr).order_by('nessusid')

    if request.GET.has_key('limit'):
        plugins = plugins[:int(request.GET['limit'])]
    
    try:
        r = set()
        [r.add(str(i['nessusid'])) for i in plugins.values('nessusid')]
        resp = '\n'.join(r)

        return HttpResponse(resp)
    except Exception, e:
        print str(e)
