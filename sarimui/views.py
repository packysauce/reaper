# Create your views here.
from django.http import HttpResponse
from django.shortcuts import render_to_response
from sarimui.models import *
from utils.bobdb import *
from django.db import connection
from datetime import *

def index(request):
    render_dict = dict()
    vuln_days = 7

    results = list(ScanResults.objects.filter(end__gte=date.today()-timedelta(days=vuln_days), state='up', vulns__isnull=False))
    
    render_dict['vulns'] = dict() 
    render_dict['vuln_head'] = ['IP Address', 'Vulnerabilities']

    for result in results:
        ip = ntoa(result.ip_id)
        try:
            render_dict['vulns'][ip]
        except:
            render_dict['vulns'][ip] = set()

        [render_dict['vulns'][ip].add( tuple(i.split('|')) ) for i in result.vulns.split(',') ] 

    #raise ValueError("Diagnostically relevant")
    return render_to_response('index.html',render_dict)

def plugin_view(request, plugin):
    return HttpResponse("Plugin {0}".format(plugin))

def ip_view_core(ip, days_back):
    render_dict = dict()
    render_dict['category'] = 'IP'
    render_dict['entry'] = ip
    render_dict['days_back'] = days_back

    #Grab the IP object and all the scanresults for it
    try:
        _ip = IpAddress.objects.get(ip=aton(ip))
    except:
        return render_to_response('view.html', render_dict)

    dtime = datetime.now() - timedelta(days=days_back)
    if days_back == -1:
        results = list(ScanResults.objects.filter(ip=_ip, state='up'))
    else:
        results = list(ScanResults.objects.filter(ip=_ip, state='up', end__gte=dtime))

    #setup for the data structure to pass to the template
    render_dict['entries'] = dict()
    
    #I flesh out the dict here to make sure that if a MAC has no data it is shown as being empty instead of not present
    for i in _ip.macs.all():
        mac = i.mac
        render_dict['entries'][mac] = dict()
        render_dict['entries'][mac]['scans'] = []
        render_dict['entries'][mac]['vuln_total'] = 0
        render_dict['entries'][mac]['name'] = ''
        render_dict['entries'][mac]['hr_name'] = 'Hostname'
        render_dict['entries'][mac]['alt_name'] = ''

    #nab all the mac<->ip associations for this ip
    macips = list(_ip.macip_set.all())

    #loop through each mac<->ip association and compare the time to the scan time
    for assoc in macips:
        #grab the iphostname association with the same ip and timestamps to get the hostname
        if render_dict['entries'][assoc.mac.mac]['name'] == '':
            hostnames = list(IpHostname.objects.filter(ip=_ip, observed__gte=assoc.observed, entered__lte=assoc.entered))
            render_dict['entries'][assoc.mac.mac]['alt_name'] = assoc.mac.mac
            if len(hostnames) > 0:
                render_dict['entries'][assoc.mac.mac]['name'] = hostnames[0].hostname
            else:
                render_dict['entries'][assoc.mac.mac]['name'] = 'NoNameAvailable'
            
        for scan in results:
            #if the scan ended when this mac<->ip assoc was active, that's the mac we need
            if (scan.end >= assoc.observed) and (scan.end <= assoc.entered):
                try:
                    #try and get the vulnerabilities out of it
                    vulns = scan.vulns.split(',')
                    render_dict['entries'][assoc.mac.mac]['vuln_total'] += len(vulns)
                    vulns = [i.split('|') for i in vulns]
                    
                except:
                    vulns = []
                #add the scan and its vulnerabilities to the rendering structure
                render_dict['entries'][assoc.mac.mac]['scans'].append( ( scan, vulns ) )

    return render_to_response('view.html', render_dict)

def host_view_core(hostname, days_back):
    render_dict = dict()
    render_dict['entry'] = hostname
    render_dict['category'] = 'MAC'
    render_dict['days_back'] = days_back

    try:
        hostobj = Hostname.objects.get(hostname=hostname)
    except:
        return render_to_response('view.html', render_dict)

    addresses = hostobj.ipaddress_set.all()
    iphosts = hostobj.iphostname_set.all()

    results = []

    render_dict['entries'] = dict()

    dtime = datetime.now()-timedelta(days=days_back)
    for ip in set(addresses):
        render_dict['entries'][ip] = dict()
        render_dict['entries'][ip]['scans'] = []
        render_dict['entries'][ip]['vuln_total'] = 0
        if days_back != -1:
            results += ScanResults.objects.filter(ip=ip.ip, end__gte=dtime)
        else:
            results += ScanResults.objects.filter(ip=ip.ip)

    for iphost in iphosts:
        macs = MacIp.objects.filter(ip = iphost.ip, observed=iphost.observed, entered=iphost.entered)
        render_dict['entries'][iphost.ip]['hr_name'] = 'MAC'
        if len(macs) > 0:
            render_dict['entries'][iphost.ip]['name'] = macs[0].ip
            render_dict['entries'][iphost.ip]['alt_name'] = macs[0].mac
        else:
            render_dict['entries'][iphost.ip]['name'] = "NoNameAvailable"

        for scan in results:
            if (scan.end >= iphost.observed) and (scan.start <= iphost.entered):
                try:
                    #try and get the vulnerabilities out of it
                    vulns = scan.vulns.split(',')
                    render_dict['entries'][iphost.ip]['vuln_total'] += len(vulns)
                    vulns = [i.split('|') for i in vulns]
                except:
                    vulns = []
                #add the scan and its vulnerabilities to the rendering structure
                render_dict['entries'][iphost.ip]['scans'].append( ( scan, vulns ) )

    return render_to_response('view.html', render_dict)

def mac_view_core(mac, days_back):
    render_dict = dict()
    render_dict['category'] = 'IP'
    render_dict['entry'] = mac
    render_dict['days_back'] = days_back

    try:
        macobj = Mac.objects.get(mac=mac)
    except:
        return render_to_response('view.html', render_dict)

    addresses = list(macobj.ipaddresses.all())
    macips = list(macobj.macip_set.all())

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

    render_dict['entries'] = dict()

    dtime = datetime.now() - timedelta(days=days_back)
    for ip in set(addresses):
        aip = ntoa(ip.ip)
        if days_back == -1:
            results = list(ScanResults.objects.filter(ip=ip.ip))
        else:
            results = list(ScanResults.objects.filter(ip=ip.ip, end__gte=dtime))
        for scan in results:
            try:
                render_dict['entries'][aip]
                render_dict['entries'][aip]['scans']
                render_dict['entries'][aip]['vuln_total']
            except:
                render_dict['entries'][aip] = dict()
                render_dict['entries'][aip]['scans'] = []
                render_dict['entries'][aip]['vuln_total'] = 0
                render_dict['entries'][aip]['name'] = aip

            if scan.vulns:
                vulns = scan.vulns.split(',')
                render_dict['entries'][aip]['vuln_total'] += len(vulns)
                vulns = [i.split('|') for i in vulns]
            else:
                vulns = []

            for first, last in timestamps[aip]:
                if (scan.end <= last) and (scan.start >= first):
                    render_dict['entries'][aip]['scans'].append( ( scan, vulns) )

    for ip in iphtimes:
        htimes = iphtimes[ip]
        for ifirst, ilast in timestamps[ip]:
            for hfirst, hlast, hostname in htimes:
                if hfirst == ifirst and hlast == ilast:
                    render_dict['entries'][ip]['alt_name'] = hostname
    
    return render_to_response('view.html', render_dict)

def scan_view(request, scan):
    render_dict = dict()
    render_dict['id'] = scan
    try:
        scanobj = ScanRun.objects.get(id=scan)
    except:
        return render_to_response('scan_view.html', render_dict)

    render_dict['scan'] = scanobj
    render_dict['hosts'] = []

    scanresults = [i.ip.ip for i in ScanResults.objects.filter(scanrun=scanobj, state='up')]

    for i in scanobj.hostset.iplist:
        if i in scanresults:
            render_dict['hosts'].append( (ntoa(i), 'up') )
        else:
            render_dict['hosts'].append( (ntoa(i), 'down') )

    return render_to_response('scan_view.html', render_dict)

def mac_view(request, mac):
    return mac_view_core(mac, -1)

def dashboard_mac_view(request, mac):
    return mac_view_core(mac, 7)

def hostname_view(request, hostname):
    return host_view_core(hostname, -1)

def dashboard_host_view(request, hostname):
    return host_view_core(hostname, 7)

def ip_view(request, ip):
    return ip_view_core(ip, -1)

def dashboard_ip_view(request, ip):
    return ip_view_core(ip, 7)
