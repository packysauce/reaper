# Create your views here.
from django.http import HttpResponse
from django.shortcuts import render_to_response
from sarimui.models import *
from utils.bobdb import *
from django.db import connection

def index(request):
    return HttpResponse("LOL HAI")

def plugin_view(request, plugin):
    return HttpResponse("Plugin {0}".format(plugin))

def scan_view(request, scan):
    render_dict = dict()
    render_dict['id'] = scan
    try:
        scanobj = ScanRun.objects.get(id=scan)
    except:
        return render_to_response('scan_view.html', render_dict)

    render_dict['scan'] = scanobj
    render_dict['hosts'] = []

    [render_dict['hosts'].append(ntoa(i)) for i in scanobj.hostset.iplist]

    return render_to_response('scan_view.html', render_dict)

def mac_view(request, mac):
    render_dict = dict()
    render_dict['mac'] = mac
    try:
        macobj = Mac.objects.get(mac=mac)
    except:
        return render_to_response('mac_view.html', render_dict)

    addresses = macobj.ipaddresses.all()
    macips = macobj.macip_set.all()

    results = []
    timestamps = dict()
    iphtimes = dict()

    for i in macips:
        for j in IpHostname.objects.filter(ip=i.ip):
            try:
                iphtimes[ntoa(i.ip.ip)].append( ( j.observed, j.entered, j.hostname ) )
            except:
                iphtimes[ntoa(i.ip.ip)] = []
                iphtimes[ntoa(i.ip.ip)].append( ( j.observed, j.entered, j.hostname ) )
        try:
            timestamps[ntoa(i.ip.ip)].append( ( i.observed, i.entered ) )
        except:
            timestamps[ntoa(i.ip.ip)] = []
            timestamps[ntoa(i.ip.ip)].append( ( i.observed, i.entered ) )

    

    render_dict['ips'] = dict()

    for ip in set(addresses):
        aip = ntoa(ip.ip)
        for scan in ScanResults.objects.filter(ip=ip.ip):
            try:
                render_dict['ips'][aip]
                render_dict['ips'][aip]['scans']
                render_dict['ips'][aip]['vuln_total']
            except:
                render_dict['ips'][aip] = dict()
                render_dict['ips'][aip]['scans'] = []
                render_dict['ips'][aip]['vuln_total'] = 0

            if scan.vulns:
                vulns = scan.vulns.split(',')
                render_dict['ips'][aip]['vuln_total'] += len(vulns)
                vulns = [i.split('|') for i in vulns]
            else:
                vulns = []

            for first, last in timestamps[aip]:
                if (scan.end <= last) and (scan.start >= first):
                    render_dict['ips'][aip]['scans'].append( ( scan, vulns) )

    for ip in iphtimes:
        htimes = iphtimes[ip]
        for ifirst, ilast in timestamps[ip]:
            for hfirst, hlast, hostname in htimes:
                if hfirst == ifirst and hlast == ilast:
                    render_dict['ips'][ip]['hostname'] = hostname
    
    return render_to_response('mac_view.html', render_dict)


def hostname_view(request, hostname):
    render_dict = dict()
    render_dict['hostname'] = hostname
    try:
        hostobj = Hostname.objects.get(hostname=hostname)
    except:
        return render_to_response('hostname_view.html', render_dict)

    addresses = hostobj.ipaddress_set.all()
    iphosts = hostobj.iphostname_set.all()

    results = []

    render_dict['ips'] = dict()

    for ip in set(addresses):
        render_dict['ips'][ip] = dict()
        render_dict['ips'][ip]['scans'] = []
        render_dict['ips'][ip]['vuln_total'] = 0
        results += ScanResults.objects.filter(ip=ip.ip)

    for iphost in iphosts:
        macs = MacIp.objects.filter(ip = iphost.ip, observed=iphost.observed, entered=iphost.entered)
        if len(macs) > 0:
            render_dict['ips'][iphost.ip]['mac'] = macs[0]
        else:
            render_dict['ips'][iphost.ip]['mac'] = "NoMACAvailable"

        for scan in results:
            if (scan.end >= iphost.observed) and (scan.start <= iphost.entered):
                try:
                    #try and get the vulnerabilities out of it
                    vulns = scan.vulns.split(',')
                    render_dict['ips'][iphost.ip]['vuln_total'] += len(vulns)
                    vulns = [i.split('|') for i in vulns]
                except:
                    vulns = []
                #add the scan and its vulnerabilities to the rendering structure
                render_dict['ips'][iphost.ip]['scans'].append( ( scan, vulns ) )

    return render_to_response('hostname_view.html', render_dict)

def ip_view(request, ip):
    render_dict = dict()
    render_dict['ip'] = ip

    #Grab the IP object and all the scanresults for it
    try:
        _ip = IpAddress.objects.get(ip=aton(ip))
    except:
        return render_to_response('ip_view.html', render_dict)

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

    return render_to_response('ip_view.html', render_dict)
