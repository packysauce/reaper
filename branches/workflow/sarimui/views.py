# Create your views here.
from datetime import *
from django.http import *
from django.shortcuts import render_to_response
from django.db import connection
from django.core.exceptions import *
from django.core.urlresolvers import reverse
from sarimui.models import *
from utils.falsepositives import FalsePositivesHelper as fphelper
from utils.bobdb import *
from utils.djangolist import *
import pprint

FLAG_FP = 1
HIDE_FP = 0

#Default view, sorted by vulnerability and spread
def ips_by_vuln(request):
    render_dict = {'pagetitle':'Vulnerabilities'}
    try:
        days_back = int(request.GET['days'])
    except:
        days_back = 7
    fp = fphelper()
    fp_option = FLAG_FP

    render_dict['days_back'] = days_back

    if 'fp' in [i.lower() for i in request.GET.keys()] and int(request.GET['fp']) in [0,1]:
        fp_option = int(request.GET['fp'])

    #Get all the scan results in the past week
    #Casting to list forces Django to evaluate the query and cache the results
    timespan = date.today()-timedelta(days=days_back)
    results = list(ScanResults.objects.filter(end__gte=timespan, state='up', vulns__isnull=False))
    scanruns = list(ScanRun.objects.filter(end__gte=timespan))
    scansets = list(ScanSet.objects.filter(entered__gte=timespan))

    #Set up the structures
    vuln_list = []
    scan_types = {}
    #id_cache is where we keep track of the index in vuln_list for a particular vulnerability id
    id_cache = {}

    for result in results:
        #This is an attempt to cache all of the scan types, as well as caching duplicate scanruns and scansets
        if result.scanrun_id not in scan_types.keys():
            scanrunidx = get_index_by_attr(scanruns, "id", result.scanrun_id)
            scansetidx = get_index_by_attr(scansets, "id", scanruns[scanrunidx].scanset_id)
            scan_types[result.scanrun_id] = scansets[scansetidx].type

        ip = ntoa(result.ip_id)
        #Vulnerability lists look like this: "description (port/proto)|#####,description (port/proto)|#####"
        #break up vulnerabilities into a list of tuples [(general (443/tcp), 22648), (description (port/proto), #####)]
        vuln_data = [tuple(i.split('|')) for i in result.vulns.split(',')]
        #For each vulnerability in the ScanResult we're looking at...
        for v in vuln_data:
            vdesc = v[0]
            vid = int(v[1])
            
            #set up the false positive flag. If this flag is set, the row will be marked as a false positive.
            #if the flag is not set, the row will not be displayed
            fp_flag = False
            if fp.is_falsepositive(ip, vid):
                if fp_option == FLAG_FP:
                    fp_flag = True
                else:
                    continue

            # if the current vulnerability is in the cache...
            if vid in id_cache.keys():
                #grab the cached index
                c = id_cache[vid]
                if ip not in [i[0] for i in vuln_list[c]['ips']]:
                    #if the ip IS NOT in the list of ips afflicted by this vuln,
                    #add it to the list...
                    vuln_list[c]['ips'].append( [ip, result, scan_types[result.scanrun_id], fp_flag] )
                else:
                    #...otherwise replace the associated ScanResult
                    #this serves to "replace if newer" since ScanResults are ordered by time
                    idx = [i for i,r,s,f in vuln_list[c]['ips']].index(ip)
                    vuln_list[c]['ips'][idx][1] = result
            # if the current vulnerability is NOT in the cache...
            else:
                #create a hash entry for each vuln and add it to the vulnerability list
                reshash = {'vid':vid, 'vname':vdesc, 'ips':[[ip,result, scan_types[result.scanrun_id], fp_flag],]}
                vuln_list.append(reshash)
                id_cache[vid] = len(vuln_list)-1

    def vsort(x):
        return len(x['ips'])
    for i in range(0,len(vuln_list)):
        vuln_list[i]['ips'].sort(lambda x,y: int(aton(x[0])-aton(y[0])))

    hostname_list = {}

    for v in vuln_list:
        for ip in v['ips']:
            if ip not in hostname_list.keys():
                try:
                    hostname_list[ip[0]] = IpHostname.objects.filter(ip=aton(ip[0])).latest().hostname.hostname
                except:
                    hostname_list[ip[0]] = "NA"

    render_dict['hostname_list'] = hostname_list

    plugin_list = {}

    for v in vuln_list:
        if v['vid'] not in plugin_list.keys():
            plugin_list[v['vid']] = Plugin.objects.filter(nessusid = v['vid']).latest()

    render_dict['plugin_list'] = plugin_list
    render_dict['vuln_list'] = sorted(vuln_list, key=vsort, reverse=True)

    return render_to_response('vulnerabilities/ips_by_vuln.html', render_dict)

def vulns_by_ip(request):
    render_dict = {'pagetitle':'Vulnerabilities', 'subtitle': 'By IP'}
    try:
        days_back = int(request.GET['days'])
    except:
        days_back = 7
    fp = fphelper()
    fp_option = FLAG_FP

    render_dict['days_back'] = days_back

    if 'fp' in [i.lower() for i in request.GET.keys()] and int(request.GET['fp']) in [0,1]:
        fp_option = int(request.GET['fp'])

    timespan = date.today()-timedelta(days=days_back)
    results = list(ScanResults.objects.filter(end__gte=timespan, state='up', vulns__isnull=False))
    scanruns = list(ScanRun.objects.filter(end__gte=timespan))
    scansets = list(ScanSet.objects.filter(entered__gte=timespan))

    vuln_list = []
    vuln_count = {}
    scan_types = {}
    id_cache = {}
    for result in results:
        if result.scanrun_id not in scan_types.keys():
            scanrunidx = get_index_by_attr(scanruns, "id", result.scanrun_id)
            scansetidx = get_index_by_attr(scansets, "id", scanruns[scanrunidx].scanset_id)
            scan_types[result.scanrun_id] = scansets[scansetidx].type

        ip = ntoa(result.ip_id)
        vuln_data = [tuple(i.split('|')) for i in result.vulns.split(',')]

        for v in vuln_data:
            vdesc = v[0]
            vid = int(v[1])
                
            #set up the false positive flag. If this flag is set, the row will be marked as a false positive.
            #if the flag is not set, the row will not be displayed
            fp_flag = False
            if fp.is_falsepositive(ip, vid):
                if fp_option == FLAG_FP:
                    fp_flag = True
                else:
                    continue

            if ip in id_cache.keys():
                c = id_cache[ip]
                if v not in vuln_list[c]['vulns']:
                    vuln_list[c]['vulns'].add(v)
                    vuln_list[c]['resmap'].append( (v,result, scan_types[result.scanrun_id], fp_flag) )
            else:
                reshash = {'ip':ip, 'vulns':set([v,]), 'resmap':[(v,result, scan_types[result.scanrun_id], fp_flag),]}
                vuln_list.append(reshash)
                id_cache[ip] = len(vuln_list)-1
    
    hostname_list = {}
    for v in vuln_list:
        ip = v['ip']
        if ip not in hostname_list.keys():
            try:
                hostname_list[ip] = IpHostname.objects.filter(ip=aton(ip)).latest().hostname.hostname
            except:
                hostname_list[ip] = "NA"

    render_dict['hostname_list'] = hostname_list

    pprint.pprint(hostname_list)
    def ipsort(x):
        return aton(x['ip'])
    render_dict['vuln_list'] = sorted(vuln_list, key=ipsort)

    return render_to_response('vulnerabilities/vulns_by_ip.html', render_dict)

def index(request):
    handlers = {'ip': vulns_by_ip, 'vulns':ips_by_vuln}
    try:
        return handlers[request.GET['view']](request)
    except KeyError, e:
        return handlers['vulns'](request)

def plugin_view(request, plugin, version):
    render_dict = {}
    render_dict['plugin'] = plugin

    if version == 'latest':
        p = Plugin.objects.filter(nessusid=plugin).latest()
        render_dict['version'] = p.version
    else:
        render_dict['version'] = Plugin.objects.get(nessusid=plugin, version=version).latest().version

    return render_to_response("plugins/plugin.html", render_dict)

def plugin_list_view(request, plugin):
    return HttpResponse("List of things with this vulnerability found, part of the scan, etc goes here")

def plugin_info_view(request, plugin, version):
    render_dict = {'pagetitle': 'Plugins', 'subtitle': 'Details'}
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

    return render_to_response('plugins/plugin_info.html', render_dict)

def ip_view_core(ip, days_back):
    render_dict = {'pagetitle': 'Devices', 'subtitle': 'IP'}
    render_dict['category'] = 'IP'
    render_dict['entry'] = ip

    #Grab the IP object and all the scanresults for it
    try:
        _ip = IpAddress.objects.get(ip=aton(ip))
    except:
        return -1

    false_positives = fphelper(ip = anytoa(ip))

    try:
        comments = list(IpComments.objects.filter(ip=_ip))
    except:
        comments = []

    if days_back == 0:
        results = list(ScanResults.objects.filter(ip=_ip, state='up'))
    else:
        dtime = datetime.now() - timedelta(days=days_back)
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
        render_dict['entries'][mac]['comments'] = []

    #nab all the mac<->ip associations for this ip
    macips = list(_ip.macip_set.all())

    #loop through each mac<->ip association and compare the time to the scan time
    for assoc in macips:
        #grab the iphostname association with the same ip and timestamps to get the hostname
        #also get the comments for the entry
        mac = assoc.mac.mac
        
        render_dict['entries'][mac]['comments'] += list(IpComments.objects.filter(ip=_ip, entered__gte=assoc.observed, entered__lte=assoc.entered))

        if render_dict['entries'][mac]['name'] == '':
            hostnames = list(IpHostname.objects.filter(ip=_ip, observed__gte=assoc.observed, entered__lte=assoc.entered))
            render_dict['entries'][mac]['alt_name'] = mac
            if len(hostnames) > 0:
                render_dict['entries'][mac]['name'] = hostnames[0].hostname.hostname
            else:
                render_dict['entries'][mac]['name'] = 'NoNameAvailable'
            
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
                fpvulns = [ (x,y,false_positives.is_falsepositive(ip,y)) for (x,y) in vulns ]
                render_dict['entries'][assoc.mac.mac]['scans'].append( ( scan, fpvulns ) )


    return render_dict

def host_view_core(hostname, days_back):
    render_dict = {'pagetitle': 'Devices', 'subtitle': 'Hostname'}
    render_dict['entry'] = hostname
    render_dict['category'] = 'MAC'

    try:
        hostobj = Hostname.objects.get(hostname=hostname)
    except:
        return -1

    addresses = hostobj.ipaddress_set.all()
    iphosts = hostobj.iphostname_set.all()

    results = []

    render_dict['entries'] = dict()

    for ip in set(addresses):
        render_dict['entries'][ip] = dict()
        render_dict['entries'][ip]['scans'] = []
        render_dict['entries'][ip]['vuln_total'] = 0
        if days_back != 0:
            dtime = datetime.now()-timedelta(days=days_back)
            results += ScanResults.objects.filter(ip=ip.ip, end__gte=dtime)
        else:
            results += ScanResults.objects.filter(ip=ip.ip)

    for iphost in iphosts:
        macs = MacIp.objects.filter(ip = iphost.ip, observed=iphost.observed, entered=iphost.entered)
        render_dict['entries'][iphost.ip]['hr_name'] = 'MAC'
        false_positives = fphelper(ip=iphost.ip)
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
                fpvulns = [ (x,y,false_positives.is_falsepositive(iphost.ip,y)) for (x,y) in vulns ]

                #add the scan and its vulnerabilities to the rendering structure
                render_dict['entries'][iphost.ip]['scans'].append( ( scan, fpvulns ) )

    return render_dict

def mac_view_core(mac, days_back):
    render_dict = {'pagetitle': 'Devices', 'subtitle': 'MAC Address'}
    render_dict['category'] = 'IP'
    render_dict['entry'] = mac

    try:
        macobj = Mac.objects.get(mac=mac)
    except:
        return -1

    dtime = datetime.now() - timedelta(days=days_back)
    if days_back == 0:
        addresses = list(macobj.ipaddresses.all())
        macips = list(macobj.macip_set.all())
    else:
        addresses = list(macobj.ipaddresses.filter(macip__entered__gte=dtime))
        macips = list(macobj.macip_set.filter(entered__gte=dtime))

    results = []
    timestamps = {}
    iphtimes = {}

    #for every macip association, get the IP of it and get all the hostname associations
    for i in macips:
        nice_ip = ntoa(i.ip_id)
        for j in IpHostname.objects.filter(ip=i.ip_id):
            #Throw it in the ip<->hostname association table
            if nice_ip in iphtimes.keys():
                iphtimes[nice_ip] += [( j.observed, j.entered, j.hostname )]
            else:
                iphtimes[nice_ip] = [( j.observed, j.entered, j.hostname )]
        # then go through and add all the start and stop dates of ip assocations
        # to the timestamp dict
        if nice_ip in timestamps.keys():
            timestamps[nice_ip] += [( i.observed, i.entered )]
        else:
            timestamps[nice_ip] = [( i.observed, i.entered )]

    render_dict['entries'] = {}

    #Converting to a set eliminates all of the duplicates
    #for each unique IP address
    #get the scan results for all the spans of time its associated
    for ip in set(addresses):
        num_ip = ip.ip
        nice_ip = ntoa(ip.ip)
        false_positives = fphelper(ip=nice_ip)
        if days_back == 0:
            results = list(ScanResults.objects.filter(ip=num_ip))
        else:
            results = list(ScanResults.objects.filter(ip=num_ip, end__gte=dtime))

        for scan in results:
            if nice_ip not in render_dict['entries'].keys():
                render_dict['entries'][nice_ip] = {'scans': [], 'vuln_total': 0, 'name': nice_ip}
            if scan.vulns:
                vulns = scan.vulns.split(',')
                render_dict['entries'][nice_ip]['vuln_total'] += len(vulns)
                vulns = [i.split('|') for i in vulns]
            else:
                vulns = []

            fpvulns = [ (x,y,false_positives.is_falsepositive(nice_ip,y)) for (x,y) in vulns ]

            for first, last in timestamps[nice_ip]:
                if (scan.end <= last) and (scan.start >= first):
                    render_dict['entries'][nice_ip]['scans'].append( ( scan, fpvulns) )

    # iphtimes is a hash of { ip: (start association, end association, hostname) }
    for ip in iphtimes:
        htimes = iphtimes[ip]
        #Grab the ip association times for this MAC
        for ifirst, ilast in timestamps[ip]:
            #Grab the hostname associations for this IP
            for hfirst, hlast, hostname in htimes:
                #if the hostname and ip associations match up, that's the hostname
                if hfirst == ifirst and hlast == ilast:
                    try:
                        render_dict['entries'][ip]['alt_name'] = hostname
                    except:
                        pass #really really weird
    
    return render_dict

def scan_view(request, scan):
    render_dict = {'pagetitle': 'Scans', 'subtitle': 'Details'}
    render_dict['id'] = scan
    try:
        scanobj = ScanRun.objects.get(id=scan)
    except:
        return render_to_response('scans/scan_view.html', render_dict)

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

    hostlen = len(render_dict['hosts'])
    if hostlen > 1:
        render_dict['result_height'] = hostlen/4*19
        if hostlen > 3:
            render_dict['result_width'] = 1000
        else:
            render_dict['result_width'] = [250,500,750][hostlen-1]
        if render_dict['result_height'] == 0:
            render_dict['result_height'] = 25

    return render_to_response('scans/scan_view.html', render_dict)

def device_search(request):
    render_dict = {'pagetitle': 'Devices', 'subtitle': 'Search'}
    render_dict['category'] = "Device"
    render_dict['search_header'] = "Enter an IP or MAC address, or hostname"
    what = ''
    for i in request.GET.keys():
        if i.lower() == 'q':
            what = request.GET[i]
            break
    else:
        return render_to_response('search.html',render_dict)

    import re
    short_ip_re = re.compile(r"\d{1,3}\.\d{1,3}")
    ip_re = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    mac_re = re.compile(r"([a-fA-F0-9]{2}:){1,}")

    if ip_re.match(what):
        results = list(IpAddress.objects.filter(ip=aton(what)))
    elif short_ip_re.match(what):
        what = '129.57.' + what
        results = list(IpAddress.objects.filter(ip=aton(what)))
    elif mac_re.match(what):
        results = list(Mac.objects.filter(mac__icontains=what))
    else:
        results = list(Hostname.objects.filter(hostname__icontains=what))

    if type(results) == int:
        if search_results == -1:
            render_dict['errors'] = ['No results found']
    else:
        fixed_results = []
        if len(results) > 1:
            for r in results:
                fixed_results.append( {
                    'url': reverse('device', args=[r]),
                    'summary': '',
                    'description': r,
                    } )
        elif len(results) == 1:
            return HttpResponseRedirect(reverse('device',args=[what]))
            #[Hostname.objects.get(hostname__icontains=what).hostname]))
        else:
            render_dict['errors'] = ['No results found']

        render_dict['results'] = fixed_results

    return render_to_response('search.html', render_dict)

def device_view(request, what):
    days_back = 7
    if what == 'search':
        what = request.GET['q']

    for i in request.GET.keys():
        if 'days' == i.lower():
            days_back = int(request.GET[i])

    return device_view_core(what, days_back)

def device_view_core(what, days_back):
    import re

    ip_re = re.compile("(\d{1,3}\.){3}\d{1,3}")
    mac_re = re.compile("([a-fA-F0-9]{2}:){5}[a-fA-F0-9]")

    if ip_re.match(what):
        render_dict = ip_view_core(what, days_back)
    elif mac_re.match(what):
        render_dict = mac_view_core(what, days_back)
    else:
        render_dict = host_view_core(what, days_back)

    if type(render_dict) == int:
        return HttpResponseRedirect(reverse('device_search'))

    render_dict['days_back'] = days_back

    return render_to_response('devices/view.html', render_dict)

def fp_view(request, fp_id):
    render_dict = {'pagetitle': 'False Positives', 'subtitle': 'Details'}

    fp = FalsePositive.objects.get(id=fp_id)
    plugin = Plugin.objects.get(nessusid=fp.nessusid, version=fp.version)
    
    render_dict['fp'] = fp
    render_dict['plugin'] = plugin
    (render_dict['fp_includes'], render_dict['fp_excludes']) = fphelper.get_lists_from_fp(fp)

    return render_to_response('false_positives/false_positive.html', render_dict)

def fp_search(request):
    render_dict = {'pagetitle':'False Positives', 'subtitle':'Search'}
    render_dict['category'] = "False Positive"

    if 'q' in request.GET.keys():
        search_term = request.GET['q']

        search_in = 'includes'
        if 'in' in request.GET.keys():
            if request.GET['in'].lower() == 'ex':
                search_in = 'excludes'

        fplist = fphelper.get_false_positives_by_ip(**{search_in: search_term})
    else:
        fplist = list(FalsePositive.objects.filter(active=True))

    result_list = []

    if len(fplist) > 1:
        for f in fplist:
            p = Plugin.objects.get(nessusid = f.nessusid, version = f.version)
            result_list.append( {
                'url': reverse('fp_detail', args=[f.id]),
                'summary': p.name + ' - ' + p.summary,
                'description': 'Nessus ID %d' % p.nessusid
                } )
    elif len(fplist) == 1:
        return HttpResponseRedirect(reverse('fp_detail',args=[fplist[0].id]))

    render_dict['results'] = result_list

    return render_to_response('false_positives/fp_search.html', render_dict)

def scan_search(request):
    render_dict = {'pagetitle': 'Scans', 'subtitle': 'Search'}
    render_dict['category'] = "Scan"
    render_dict['search_header'] = "Enter a Scan ID"
    what = ''
    for i in request.GET.keys():
        if i.lower() == 'q':
            what = request.GET[i]
            break
    else:
        return render_to_response('search.html',render_dict)

    try:
        ScanRun.objects.get(id=what)
    except:
        render_dict['errors'] = ["No scan with ID " + str(what) + " found.",]
        return render_to_response('search.html', render_dict)

    return HttpResponseRedirect(reverse('scan', args=[what]))

def plugin_search(request):
    render_dict = {'pagetitle': 'Plugins', 'subtitle': 'Search'}
    render_dict['category'] = "Plugin"
    render_dict['search_header'] = "Enter a Nessus ID"
    what = ''
    for i in request.GET.keys():
        if i.lower() == 'q':
            what = request.GET[i]
            break
    else:
        return render_to_response('search.html',render_dict)

    try:
        Plugin.objects.get(nessusid=what)
    except:
        render_dict['errors'] = ["No plugin with Nessus ID " + str(what) + " found.",]
        return render_to_response('search.html', render_dict)

    return HttpResponseRedirect(reverse('plugin', args=[what, 'latest']))

def fp_create(request):
    import json

    inc = request.POST['include']
    if not SARIMUI_IP_RE.match(inc):
        #Include must be an ip, so if its not an IP, go get one
        if SARIMUI_MAC_RE.match(inc):
            #It's a MAC, grab the most recent macip association
            inc = ntoa(MacIp.objects.filter(mac__mac=inc).latest().ip_id)
        else:
            #assume it's a hostname
            inc = ntoa(IpHostname.objects.filter(hostname__hostname=inc).latest().ip_id)

    try:
        try:
            fp = FalsePositive.objects.get(nessusid=request.POST['nessusid'])
            if inc not in fp.includes:
                fp.includes += "," + inc
                fp.save()
        except ObjectDoesNotExist, e:
            newfp = FalsePositive()
            plug = Plugin.objects.filter(nessusid=request.POST['nessusid']).latest()
            newfp.nessusid = plug.nessusid
            newfp.version = plug.version
            newfp.added_by = 'user'
            newfp.includes = inc
            newfp.comment = 'comment'
            newfp.active = True
            newfp.save()
        except Exception, e:
            return HttpResponse( json.dumps( { 'result': 'failure', 'error': str(e), } ) )

        return HttpResponse( json.dumps( { 'result': 'success', 'nessusid':request.POST['nessusid']}))
    except Exception, e:
        return HttpResponse( json.dumps( { 'result': 'failure', 'error': str(e), } ) )

