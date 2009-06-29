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

def hostname_view(request, hostname):
    return HttpResponse("Hostname {0}".format(hostname))

def ip_view(request, ip):
    render_dict = dict()

    #Grab the IP object and all the scanresults for it
    try:
        _ip = IpAddress.objects.get(ip=aton(ip))
    except:
        render_dict['ip'] = ip
        return render_to_response('new_ip.html', render_dict)

    results = ScanResults.objects.filter(ip=_ip, state='up')

    #setup for the data structure to pass to the template
    render_dict['macs'] = dict()
    
    for i in _ip.macs.all():
        
        mac = i.mac
        render_dict['macs'][mac] = dict()
        render_dict['macs'][mac]['scans'] = []
        render_dict['macs'][mac]['vuln_total'] = 0
        render_dict['macs'][mac]['hostname'] = ''

    #nab all the mac<->ip associations for this ip
    macips = _ip.macip_set.all()

    #loop through each mac<->ip association and compare the time to the scan time
    for assoc in macips:
        #grab the iphostname association with the same ip and timestamps to get the hostname
        if render_dict['macs'][assoc.mac.mac]['hostname'] == '':
            hostnames = IpHostname.objects.filter(ip=_ip, observed=assoc.observed, entered=assoc.entered)
            if len(hostnames) > 0:
                render_dict['macs'][assoc.mac.mac]['hostname'] = hostnames[0].hostname
            else:
                render_dict['macs'][assoc.mac.mac]['hostname'] = 'NoHostAvailable'
            
        for scan in results:
            #if the scan ended when this mac<->ip assoc was active, that's the mac we need
            if (scan.end >= assoc.observed) and (scan.end <= assoc.entered):
                try:
                    #try and get the vulnerabilities out of it
                    vulns = scan.vulns.split(',')
                    render_dict['macs'][assoc.mac.mac]['vuln_total'] += len(vulns)
                    vulns = [i.split('|') for i in vulns]
                    
                except:
                    vulns = []
                #add the scan and its vulnerabilities to the rendering structure
                render_dict['macs'][assoc.mac.mac]['scans'].append( ( scan, vulns ) )

    for i in render_dict['macs']:
        render_dict['macs'][i]['scans'].reverse()
    return render_to_response('new_ip.html', render_dict)
