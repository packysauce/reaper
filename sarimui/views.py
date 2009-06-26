# Create your views here.
from django.http import HttpResponse
from django.shortcuts import render_to_response
from sarimui.models import *
from utils.bobdb import *
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
    #first, gather all the scans with the IP
    #second, gather all the MAC associations with the IP
    #third, look at the MAC assoc. between the scan start and end times to see
    #        what MAC a particular IP was using at the time

    # ['macs'][<mac address>]
    #                       +-['scans']
    #                       +-['vulns']

    tmp_dict = dict()

    scanresults = ScanResults.objects.filter(ip=aton(ip), state='up')
    scans = set([i.scanrun for i in scanresults])
    associations = MacIp.objects.filter(ip=aton(ip))

    tmp_dict['macs'] = dict()

    #set up a dictionary of lists, where the dictionary holds the MACs
    # and the list holds all the scan results
    for mac in set([i.macid.mac for i in associations]):
        tmp_dict['macs'][mac] = dict()
        tmp_dict['macs'][mac]['scans'] = []
        tmp_dict['macs'][mac]['vuln_total'] = 0

    for assoc in associations:
        for scan in scanresults:
            if (scan.end >= assoc.observed) and (scan.end <= assoc.entered):
                try:
                    tmp_vulns = [i.split('|') for i in scan.vulns.split(',')]
                    tmp_dict['macs'][assoc.macid.mac]['vuln_total'] += len(tmp_vulns)
                except:
                    tmp_vulns = []

                entry = (scan, tmp_vulns)
                tmp_dict['macs'][assoc.macid.mac]['scans'].append(entry)

    tmp_dict['ip'] = ip

    for i in tmp_dict['macs']:
        tmp_dict['macs'][i]['scans'].reverse()

    return render_to_response('new_ip.html', tmp_dict)


