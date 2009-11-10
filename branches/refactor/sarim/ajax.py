from django.contrib.auth.decorators import permission_required
from django.http import *
from utils.bobdb import *
from devices.models import Hostname, IpAddress, Mac
from sarim.models import Comment

try:
    import json
except:
    import django.utils.simplejson as json

#@permission_required('sarim.add_comment')
def add_comment(request, object, id):
    if object == "Hostname":
        obj = Hostname.objects.get(hostname__iexact=id)
    elif object == "IP":
        obj = IpAddress.objects.get(ip=aton(id))
    elif object == "MAC":
        obj = Mac.objects.get(mac__iexact=id)
    else:
        return HttpResponseBadRequest( json.dumps( {'result':'failure', 'error':'Object not found'} ) )

    try:
        obj.comments.create(user=request.user, comment=request.POST['comment'])
    except:
        return HttpResponseBadRequest( json.dumps( {'result':'failure', 'error':'Bad data passed'} ) )
    return HttpResponse( json.dumps( {'result': 'success'} ) )
