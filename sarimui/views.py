# Create your views here.
from django.http import HttpResponse
from django.shortcuts import render_to_response
from sarimui.models import *
from utils.bobdb import *
from django.db import connection
import ipcalc

def index(request):
    return HttpResponse("LOL HAI")

def plugin_view(request, plugin):
    return HttpResponse("Plugin {0}".format(plugin))

def scan_view(request, scan):
    return HttpResponse("Scan {0}".format(scan))

def mac_view(request, mac):
    return HttpResponse("Mac {0}".format(mac))

def hostname_view(request, hostname):
    hostobj = Hostname.objects.get(hostname=hostname)
    addresses = hostobj.ipaddress_set.all()
    iphosts = hostobj.iphostname_set.all()

    results = []

    render_dict = dict()
    render_dict['ips'] = dict()

    for ip in set(addresses):
        render_dict['ips'][ntoa(ip.ip)] = dict()
        render_dict['ips'][ntoa(ip.ip)]['scans'] = []
        render_dict['ips'][ntoa(ip.ip)]['vuln_total'] = 0
        results += ScanResults.objects.filter(ip=ip.ip)

    for iphost in iphosts:
        macs = MacIp.objects.filter(ip = iphost.ip, observed=iphost.observed, entered=iphost.entered)
        if len(macs) > 0:
            render_dict['ips']iphost.ip]['mac'] = macs[0]
        else:
            render_dict['ips'][iphost.ip]['mac'] = "No MAC Available"

        for scan in results:
            if (scan.end >= iphost.entered) and (scan.start <= iphost.observed):
                try:
                    #try and get the vulnerabilities out of it
                    vulns = scan.vulns.split(',')
                    render_dict['ips'][iphost.ip]['vuln_total'] += len(vulns)
                    vulns = [i.split('|') for i in vulns]
                except:
                    vulns = []
                #add the scan and its vulnerabilities to the rendering structure
                render_dict['ips'][iphost.ip]['scans'].append( ( scan, vulns ) )

    return render_to_response('ip_view.html', render_dict)

def ip_view(request, ip):
    render_dict = dict()
    render_dict['ip'] = ip

    #Grab the IP object and all the scanresults for it
    try:
        _ip = IpAddress.objects.get(ip=aton(ip))
    except:
        return render_to_response('new_ip.html', render_dict)

    results = ScanResults.objects.filter(ip=_ip, state='up')

    #setup for the data structure to pass to the template
    render_dict['macs'] = dict()
    
    #I flesh out the dict here to make sure that if a MAC has no data it is shown as being empty instead of not present
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
    return render_to_response('ip_view.html', render_dict)
