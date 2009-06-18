# Create your views here.
from django.http import HttpResponse
from django.shortcuts import render_to_response
from sarimui.models import *
from utils.bobdb import *

def index(request):
    return HttpResponse("LOL HAI")

def ip_list(request):
    tmp_dict = dict()

    dedupe = set([ i.ip for i in IpHostname.objects.all()[0:30] ])

    tmp_dict['ip_list'] = [ ntoa(i) for i in dedupe]

    return render_to_response('ip_list.html', tmp_dict)

def ip_view(request,ip):
    

    return render_to_response('ip.html', tmp_dict)
