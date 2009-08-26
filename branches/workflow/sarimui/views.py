# Create your views here.
from django.http import HttpResponse
from django.shortcuts import render_to_response
from sarimui.models import *
from utils.bobdb import *
from django.db import connection
from datetime import *
from django.core.exceptions import *

def ips_by_vuln(request):
    render_dict = {}
    days_back = 7

    #Get all the scan results in the past week
    #Casting to list forces Django to evaluate the query and cache the results
    results = list(ScanResults.objects.filter(end__gte=date.today()-timedelta(days=days_back), state='up', vulns__isnull=False))

    #Set up the structures
    vuln_list = []
    scan_types = {}
    id_cache = {}
    cache_misses = 0

    for result in results:
        if result.scanrun_id not in scan_types.keys():
            scan_types[result.scanrun_id] = result.scanrun.scanset.type
        ip = ntoa(result.ip_id)
        #Vulnerability lists look like this: "description (port/proto)|#####,description (port/proto)|#####"
        vuln_data = [tuple(i.split('|')) for i in result.vulns.split(',')]
        for v in vuln_data:
            try:
                c = id_cache[v[1]]
                if ip not in [i[0] for i in vuln_list[c]['ips']]:
                    vuln_list[c]['ips'].append( [ip, result, scan_types[result.scanrun_id]] )
                else:
                    idx = [x for x,y,z in vuln_list[c]['ips']].index(ip)
                    vuln_list[c]['ips'][idx][1] = result
            except KeyError, e:
                reshash = {'vid':v[1], 'vname':v[0], 'ips':[[ip,result, scan_types[result.scanrun_id]],]}
                vuln_list.append(reshash)
                id_cache[v[1]] = len(vuln_list)-1
                cache_misses += 1


    def vsort(x):
        return len(x['ips'])
    for i in range(0,len(vuln_list)):
        vuln_list[i]['ips'].sort(lambda x,y: int(aton(x[0])-aton(y[0])))

    render_dict['vuln_list'] = sorted(vuln_list, key=vsort, reverse=True)

    import pprint
    pprint.pprint(render_dict)
    return render_to_response('ips_by_vuln.html', render_dict)

def vulns_by_ip(request):
    render_dict = {}
    days_back = 7

    results = ScanResults.objects.filter(end__gte=date.today()-timedelta(days=days_back), state='up', vulns__isnull=False)

    vuln_list = []
    vuln_count = {}
    id_cache = {}
    for result in results:
        ip = ntoa(result.ip_id)
        vuln_data = [tuple(i.split('|')) for i in result.vulns.split(',')]
        try:
            for v in vuln_data:
                if v not in vuln_list[id_cache[ip]]['vulns']:
                    vuln_list[id_cache[ip]]['vulns'].add(v)
                    vuln_list[id_cache[ip]]['resmap'].append((v,result))
        except KeyError, e:
            reshash = {'ip':ip, 'vulns':set(), 'resmap':[]}
            for v in vuln_data:
                if v not in reshash['vulns']:
                    reshash['vulns'].add(v)
                    reshash['resmap'].append((v,result))
            else:
                vuln_list.append(reshash)
                id_cache[ip] = len(vuln_list)-1

    def ipsort(x):
        return aton(x['ip'])
    render_dict['vuln_list'] = sorted(vuln_list, key=ipsort)

    return render_to_response('vulns_by_ip.html', render_dict)

def index(request):
    handlers = {'ip': vulns_by_ip, 'vulns':ips_by_vuln}
    try:
        return handlers[request.GET['view']](request)
    except KeyError, e:
        return handlers['vulns'](request)

def plugin_view(request, plugin):
    render_dict = {}
    render_dict['plugin'] = plugin
    try:
        render_dict['version'] = request.GET['v']
    except KeyError:
        p_all = Plugin.objects.filter(nessusid=plugin)
        p = p_all.latest()
        render_dict['version'] = p.version
    except ObjectDoesNotExist:
        render_dict['version'] = Plugin.objects.filter(nessusid=plugin).latest().version

    return render_to_response("plugin.html", render_dict)

def plugin_list_view(request, plugin):
    return HttpResponse("List of things with this vulnerability found, part of the scan, etc goes here")

def plugin_info_view(request, plugin, version):
    render_dict = {}
    render_dict['versions'] = []

    p_all = Plugin.objects.filter(nessusid=plugin)
    for plug in p_all:
        render_dict['versions'].append(plug.version)
    try:
        if version.lower() == 'latest':
            p = Plugin.objects.filter(nessusid=plugin).latest()
        else:
            p = Plugin.objects.get(nessusid=plugin, version=version)
    except ObjectDoesNotExist:
        render_dict['errormessage'] = "Invalid version selected, defaulting to latest"
        p = Plugin.objects.filter(nessusid=plugin).latest()

    render_dict['selected_version'] = p.version
    render_dict['plugin'] = p
    render_dict['cve_list'] = [i.strip() for i in p.cveid.split(',')]
    render_dict['bid_list'] = [i.strip() for i in p.bugtraqid.split(',')]

    if 'noxref' not in p.xref.lower():
        render_dict['xref_list'] = []
        xref_list = [i.strip() for i in p.xref.split(',')]
        for xref in xref_list:
            (type, id) = xref.split(':',1)
            if 'OSVDB' in type:
                href = 'http://osvdb.org/show/osvdb/' + id
                render_dict['xref_list'].append( (type, id, href) )
            if 'RHSA' in type:
                rhsaid = '%s-%s' % (id[:9], id[10:13])
                href = 'http://rhn.redhat.com/errata/%s.html' % rhsaid
                render_dict['xref_list'].append( (type, id, href) )

    #get everything ready to work on
    desc = p.description
    ldesc = desc.lower()
    index = []
    #words to look for
    words = ['synopsis','description','solution','risk factor']
    #build a list of tuples of format (<word position>, <word>)
    for word in words:
        try:
            index.append( (ldesc.index(word), word) )
        except:
            index.append( (-1, word) )
    #sort the aforementioned list according to word position
    import operator
    sindex = sorted(index, key=operator.itemgetter(0))

    for pos, word in sindex:
        #Get the tuple's position in the list of tuples
        mappos = sindex.index( (pos, word) )
        #-1 means the word wasn't found...
        if pos == -1:
            #All this does is go find the next word without a -1 position
            #and copy all of the text from the start of the description to the
            #first position found
            if word == 'description':
                x = -1
                for i in range(mappos,len(sindex)):
                    if sindex[i][0] != -1:
                        x = sindex[i][0]
                s = desc[0:x]
            else:
                continue
        else:
            if mappos == len(sindex)-1:
                s = desc[pos+len(word):]
            else:
                s = desc[pos+len(word):sindex[mappos+1][0]]

        #The nessus plugin info has some stupid escaping going on
        s = s.replace(':\\n\\n', '')
        s = s.replace('\\n', ' ')
        s = s.replace(': ', '', 1)
        #Take care of dictionary names with spaces in them
        render_dict[word.replace(' ', '')] = s

    return render_to_response('plugin/plugin_info.html', render_dict)

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
    render_dict['repairs'] = 0
    render_dict['broken_ips'] = []

    sresults = list(ScanResults.objects.filter(scanrun=scanobj, state='up'))
    scanresults = []
    for i in sresults:
        try:
            scanresults.append(i.ip.ip)
        except:
            render_dict['repairs']+=1
            render_dict['broken_ips'].append(ntoa(i.ip_id))
            nip = IpAddress(ip=i.ip_id)
            nip.save()
            scanresults.append(nip.ip)

    for i in scanobj.hostset.iplist:
        if i in scanresults:
            render_dict['hosts'].append( (ntoa(i), 'up') )
        else:
            render_dict['hosts'].append( (ntoa(i), 'down') )

    return render_to_response('scan_view.html', render_dict)

def mac_view(request, mac):
    return mac_view_core(mac, -1)

def dashboard_mac_view(request, mac):
    try:
        days = int(request.GET['days'])
    except:
        days = 7
    return mac_view_core(mac, days)

def hostname_view(request, hostname):
    return host_view_core(hostname, -1)

def dashboard_host_view(request, hostname):
    try:
        days = int(request.GET['days'])
    except:
        days = 7
    return host_view_core(hostname, days)

def ip_view(request, ip):
    return ip_view_core(ip, -1)

def dashboard_ip_view(request, ip):
    try:
        days = int(request.GET['days'])
    except:
        days = 7
    return ip_view_core(ip, days)
