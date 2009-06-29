# Create your views here.
from django.http import HttpResponse
from django.shortcuts import render_to_response
from sarimui.models import *
from utils.bobdb import *
from django.db import connection
import ipcalc

def index(request):
    return HttpResponse("LOL HAI")

def ip_list(request):
    tmp_dict = dict()

    dedupe = set([ i.ip for i in IpHostname.objects.all()[0:100] ])

    tmp_dict['ip_list'] = [ ntoa(i) for i in dedupe]

    return render_to_response('ip_list.html', tmp_dict)

def plugin_view(request, plugin):
    return HttpResponse("Plugin {0}".format(plugin))

def scan_view(request, scan):
    return HttpResponse("Scan {0}".format(scan))

def mac_view(request, mac):
    return HttpResponse("Mac {0}".format(mac))

def ip_view(request, ip):
    render_dict = dict()

    _ip = IpAddress.objects.get(ip=aton(ip))
    results = ScanResults.objects.filter(ip=_ip, state='up')

    render_dict['macs'] = dict()

    for i in _ip.macs.all():
        mac = i.mac
        render_dict['macs'][mac] = dict()
        render_dict['macs'][mac]['scans'] = []
        render_dict['macs'][mac]['vuln_total'] = 0

    macips = _ip.macip_set.all()

    for assoc in macips:
        for scan in results:
            if (scan.end >= assoc.observed) and (scan.end <= assoc.entered):
                try:
                    vulns = scan.vulns.split(',')
                    vulns = [i.split('|') for i in vulns]
                except:
                    vulns = []
                render_dict['macs'][assoc.mac.mac]['scans'].append( ( scan, vulns ) )

    for i in connection.queries:
        print i['sql'], i['time']
    print "{0} queries.".format(len(connection.queries))

    return render_to_response('new_ip.html', render_dict)
