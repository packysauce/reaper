from django.http import *
from utils.bobdb import *
from devices.models import *
from falsepositive.models import *
from django.core.exceptions import *
from django.contrib.auth.decorators import login_required, permission_required
from django.core.urlresolvers import reverse
try:
    import json
except:
    import django.utils.simplejson as json
import re

def add_to_fp(fp, what, data):
    if what == "inc":
        iplist = fp.includes
    elif what == "exc":
        iplist = fp.excludes
    else:
        return HttpResponseBadRequest( json.dumps( { 'message': 'Bad Request' } ) )

    if SARIMUI_IP_RE.match(data):
        _ip = data
    elif SARIMUI_SHORT_IP_RE.match(data):
        _ip = '129.57.'+data
    else:
        return HttpResponseBadRequest(json.dumps( {'message': 'Invalid IP'}))

    try:
        fp.include_all = False
        iplist.add(list(IpAddress.objects.get_or_create(ip=aton(_ip)))[0])
        fp.save()
        return HttpResponse( json.dumps({'ip': _ip }) )
    except Exception, e:
        return HttpResponseBadRequest(json.dumps( {'message': str(e)}))

def remove_from_fp(fp, what, data):
    if what == "inc":
        iplist = fp.includes
    elif what == "exc":
        iplist = fp.excludes
    else:
        return HttpResponseBadRequest( json.dumps( {'message': 'Bad Request' } ) )

    if SARIMUI_IP_RE.match(data):
        _ip = data
    elif SARIMUI_SHORT_IP_RE.match(data):
        _ip = '129.57.'+data
    else:
        return HttpResponseBadRequest(json.dumps( {'message': 'Invalid IP'}))

    try:
        iplist.remove(IpAddress.objects.get(ip=aton(_ip)))
        return HttpResponse( json.dumps( {'ip': _ip} ) )
    except Exception, e:
        return HttpResponseBadRequest(json.dumps( {'message':  str(e)}))

def change_fp_details(fp, comment):
    try:
        fp.comment = comment
        fp.save()
        return HttpResponse( json.dumps( {'message': 'Success'} ) )
    except:
        return HttpResponseBadRequest( json.dumps( {'message': str(e)} ) )

@permission_required('sarim.change_falsepositive')
def fp_modify(request):
    fpid = request.POST['fp']
    action = request.POST['action']

    try:
        fp = FalsePositive.objects.get(id=fpid)
    except:
        return HttpResponseBadRequest( json.dumps( { 'message': "Inavlid False Positive ID" } ) )
    
    if action.startswith('add_'):
        data = request.POST['data']
        last_three = action[-3:]
        if last_three == 'all':
            fp.include_all = True
            fp.save()
            return HttpResponse( json.dumps( { 'message': "Included All IPs" } ) )
        else:
            return add_to_fp(fp, action[-3:], data)
    elif action.startswith('remove_'):
        data = request.POST['data']
        return remove_from_fp(fp, action[-3:], data)
    elif action == "change_details":
        comments = request.POST['comments']
        return change_fp_details(fp, comments)
    else:
        return HttpResponseBadRequest( json.dumps( { 'message': "Invalid Action" } ) )

@permission_required('sarim.add_falsepositive')
def fp_create(request):

    inc = request.POST['include']
    if not SARIMUI_IP_RE.match(inc):
        #Include must be an ip, so if its not an IP, go get one
        if SARIMUI_MAC_RE.match(inc):
            #It's a MAC, grab the most recent macip association
            inc = MacIp.objects.filter(mac__mac=inc).latest().ip
        else:
            #assume it's a hostname
            inc = IpHostname.objects.filter(hostname__hostname=inc).latest().ip
    else:
        inc = IpAddress.objects.get(ip=aton(ip))

    try:
        try:
            fp = FalsePositive.objects.get(plugin__nessusid=request.POST['nessusid'])
            fp.includes.add(inc)
        except ObjectDoesNotExist, e:
            newfp = FalsePositive()
            newfp.added_by = request.user.username
            newfp.comment = 'comment'
            newfp.active = True
            newfp.plugin = Plugin.objects.filter(nessusid=request.POST['nessusid']).latest()
            newfp.save()
            newfp.includes.add(inc)
        return HttpResponse( json.dumps( { 'result': 'success', 'nessusid':request.POST['nessusid']}))
    except Exception, e:
        return HttpResponse( json.dumps( { 'result': 'failure', 'error': str(e), } ) )
