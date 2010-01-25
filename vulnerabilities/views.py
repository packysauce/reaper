from datetime import *
from django.http import *
from django.shortcuts import render_to_response
from django.db import *
from django.db.models import Q
from django.core.exceptions import *
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required, permission_required
from django.template import RequestContext
from vulnerabilities.models import *
from devices.models import *
from plugins.models import *
from scans.models import *
from falsepositives.models import *
from utils.bobdb import *
from utils.djangolist import *
from utils.permissionutils import *
from utils import gatorlink
import pprint

FLAG_FP = 1
HIDE_FP = 0

#Default view, sorted by vulnerability and spread
@login_required
def ips_by_vuln(request):
    render_dict = {'pagetitle':'Vulnerabilities'}
    start_time = datetime.now()
    userprofile = request.user.get_profile()

    if request.GET.has_key('days'):
        userprofile.default_days_back = int(request.GET['days'])
        userprofile.save()

    days_back = userprofile.default_days_back

    fp_option = FLAG_FP

    render_dict['days_back'] = days_back

    if 'fp' in [i.lower() for i in request.GET.keys()] and int(request.GET['fp']) in [0,1]:
        fp_option = int(request.GET['fp'])

    #Get all the scan results in the past week
    #Casting to list forces Django to evaluate the query and cache the results
    timespan = date.today()-timedelta(days=days_back)
    results = ScanResults.objects.filter(end__range=(timespan, datetime.now()), state='up', vulns__isnull=False)

    if len(results) == 0:
        return render_to_response('ips_by_vuln.html', render_dict, context_instance=RequestContext(request))

    run_set_map = set([ (i.scanrun_id, i.scanrun.scanset_id) for i in results])
    sets = zip(*run_set_map)[1]
    scansets = ScanSet.objects.filter(id__in = set(sets))

    scan_types = {}
    for irun, iset in run_set_map:
        scan_types[irun] = scansets.get(id=iset).type

    #Set up the structures
    vuln_list = []
    #id_cache is where we keep track of the index in vuln_list for a particular vulnerability id
    id_cache = {}

    allfps = FalsePositive.objects.all()
    for result in results:

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

            try:
                allfps.objects.get(
                    Q(includes=result.ip) | Q(include_all=True),
                    ~Q(excludes=result.ip),
                    plugin__nessusid=vid
                    )
                fp_flag = True
            except:
                fp_flag = False


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

    return render_to_response('ips_by_vuln.html', render_dict, context_instance=RequestContext(request))

@login_required
def vulns_by_ip(request):
    render_dict = {'pagetitle':'Vulnerabilities', 'subtitle': 'By IP'}
    userprofile = request.user.get_profile()

    if request.GET.has_key('days'):
        userprofile.default_days_back = int(request.GET['days'])
        userprofile.save()

    days_back = userprofile.default_days_back

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
            fp_list = FalsePositive.objects.filter(
                    Q(includes=result.ip) | Q(include_all=True),
                    ~Q(excludes=result.ip),
                    plugin__nessusid=vid
                    )
            if len(fp_list) > 0:
                fp_flag = True

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

    def ipsort(x):
        return aton(x['ip'])
    render_dict['vuln_list'] = sorted(vuln_list, key=ipsort)

    return render_to_response('vulns_by_ip.html', render_dict, context_instance=RequestContext(request))


