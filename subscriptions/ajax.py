from subscriptions.models import *
from django.http import *
from devices.models import *
from utils.bobdb import aton

try:
    import json
except:
    import django.utils.simplejson as json

def create_subscription(request):
    if request.POST.has_key('type') and request.POST['type'] in ['ip','host','mac']:
        sub_type = request.POST['type']
    else:
        return HttpResponse( json.dumps( { 'result': 'failure', 'message': 'Invalid request type'} ) )

    if request.POST.has_key('id'):
        id = request.POST['id']
    else:
        return HttpResponse( json.dumps( { 'result': 'failure', 'message': 'Invalid id specified'} ) )

    obj = None

    if sub_type == 'ip':
        try:
            obj = IpAddress.objects.get(ip=aton(id))
        except Exception, e:
            return HttpResponse( json.dumps( { 'result': 'failure', 'message': 'Error getting IP'} ) )
    elif sub_type == 'host':
        try:
            obj = Hostname.objects.get(hostname=id)
        except Exception, e:
            return HttpResponse( json.dumps( { 'result': 'failure', 'message': 'Error getting hostname'} ) )
    elif sub_type == 'mac':
        try:
            obj = Mac.objects.get(mac=id)
        except Exception, e:
            return HttpResponse( json.dumps( { 'result': 'failure', 'message': 'Error getting MAC'} ) )
    else:
        return HttpResponse( json.dumps( { 'result': 'failure', 'message': 'Bad ID specified' } ) )

    try:
        request.user.subscriptions.create(content_object=obj)
    except Exception, e:
        return HttpResponse( json.dumps( { 'result': 'failure', 'message': 'Could not create subscription' } ) )
    
    return HttpResponse( json.dumps( { 'result': 'success' } ) )
