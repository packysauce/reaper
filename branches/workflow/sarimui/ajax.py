from django.http import *
from utils.bobdb import *
from sarimui.models import *
from django.core.exceptions import *
import json
import re

def fp_modify(request):
    fpid = request.POST['fp']
    action = request.POST['action']
    data = request.POST['data']
    try:
        fp = FalsePositive.objects.get(id=fpid)
    except:
        return HttpResponseBadRequest("Inavlid False Positive ID")

    if action == 'add_inc':
        try:
            if SARIMUI_IP_RE.match(data):
                fp.includes.add(IpAddress.objects.get(ip=aton(data)))
                return HttpResponse( json.dumps({'ip': data }) )
            elif SARIMUI_SHORT_IP_RE.match(data):
                fp.includes.add(IpAddress.objects.get(ip=aton('129.57.'+data)))
                return HttpResponse( json.dumps({'ip': '129.57.'+data }) )
        except Exception, e:
            return HttpResponseBadRequest(json.dumps( {'message': 'invalid ip'}))
    elif action == 'add_exc':
        if SARIMUI_IP_RE.match(data):
            fp.excludes.add(IpAddress.objects.get(ip=aton(data)))
            return HttpResponse( json.dumps({'ip': data }) )
        elif SARIMUI_SHORT_IP_RE.match(data):
            fp.excludes.add(IpAddress.objects.get(ip=aton('129.57.'+data)))
            return HttpResponse( json.dumps({'ip': '129.57.'+data }) )
        else:
            return HttpResponseBadRequest(json.dumps( {'message': 'invalid ip'}))
    else:
        return HttpResponseBadRequest( json.dumps({'message': 'invalid action'}) )

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
            newfp.added_by = 'user'
            newfp.comment = 'comment'
            newfp.active = True
            newfp.plugin = Plugin.objects.filter(nessusid=request.POST['nessusid']).latest()
            newfp.save()
            newfp.includes.add(inc)
        return HttpResponse( json.dumps( { 'result': 'success', 'nessusid':request.POST['nessusid']}))
    except Exception, e:
        return HttpResponse( json.dumps( { 'result': 'failure', 'error': str(e), } ) )

