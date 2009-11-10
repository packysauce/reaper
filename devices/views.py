# Create your views here.
from datetime import *
from django.http import *
from django.shortcuts import render_to_response
from django.db import *
from django.db.models import Q
from django.core.exceptions import *
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required, permission_required
from django.template import RequestContext
from devices.models import *
from vulnerabilities.models import *
from utils.bobdb import *
from utils.djangolist import *
from utils.permissionutils import *
from utils import gatorlink

@login_required
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
        return render_to_response('search.html',render_dict, context_instance=RequestContext(request))

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

    return render_to_response('search.html', render_dict, context_instance=RequestContext(request))

@login_required
def device_view(request, what):
    days_back = 7
    if what == 'search':
        what = request.GET['q']

    for i in request.GET.keys():
        if 'days' == i.lower():
            days_back = int(request.GET[i])

    return device_view_core(request, what, days_back)

@login_required
@user_owns_machine
def device_view_core(request, what, days_back):
    import re

    ip_re = re.compile("(\d{1,3}\.){3}\d{1,3}")
    mac_re = re.compile("([a-fA-F0-9]{2}:){5}[a-fA-F0-9]")

    if ip_re.match(what):
        render_dict = ip_view_core(request, what, days_back)
    elif mac_re.match(what):
        render_dict = mac_view_core(request, what, days_back)
    else:
        render_dict = host_view_core(request, what, days_back)

    if type(render_dict) == int:
        return HttpResponseRedirect(reverse('device_search'))

    render_dict['days_back'] = days_back

    return render_to_response('device_view.html', render_dict, context_instance=RequestContext(request))

@login_required
def index(request):
    if request.user.is_staff:
        handlers = {'ip': vulns_by_ip, 'vulns':ips_by_vuln}
        try:
            return handlers[request.GET['view']](request)
        except KeyError, e:
            return handlers['vulns'](request)
    else:
        hostlist = get_hosts_by_user(request.user)
        return render_to_response('devices_by_user.html', {'hosts': hostlist}, context_instance=RequestContext(request))

@login_required
def ip_view_core(request, ip, days_back):
    render_dict = {'pagetitle': 'Devices', 'subtitle': 'IP'}
    render_dict['category'] = 'IP'
    render_dict['entry'] = ip

    #Grab the IP object and all the scanresults for it
    try:
        _ip = IpAddress.objects.get(ip=aton(ip))
    except:
        return -1
    render_dict['most_frequent_user'] = get_most_frequent_user(_ip.ip)
    render_dict['gator_info'] = gatorlink.Gator(str(_ip))

    render_dict['comments'] = []
    render_dict['comments'] += _ip.comments.all()

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
        render_dict['comments'] += i.comments.all()
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
        
        render_dict['entries'][mac]['comments'] += assoc.comments.all()

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
                fpvulns = []
                for (x,y) in vulns:
                    z = False
                    r = FalsePositive.objects.filter(
                            Q(includes=_ip) | Q(include_all=True),
                            ~Q(excludes=_ip),
                            plugin__nessusid = y
                            )
                    if len(r) > 0:
                        z = True
                    fpvulns.append( (x,y,z) )
                render_dict['entries'][assoc.mac.mac]['scans'].append( ( scan, fpvulns ) )

    render_dict['comments'] = sorted(render_dict['comments'], key=lambda(x): x.modified, reverse=True)
    
    return render_dict

@login_required
def host_view_core(request, hostname, days_back):
    render_dict = {'pagetitle': 'Devices', 'subtitle': 'Hostname'}
    render_dict['entry'] = hostname
    render_dict['category'] = 'MAC'
    render_dict['gator_info'] = gatorlink.Gator(hostname)

    try:
        hostobj = Hostname.objects.get(hostname=hostname)
    except:
        return -1

    current_ip = hostobj.iphostname_set.latest().ip.ip
    render_dict['most_frequent_user'] = get_most_frequent_user(current_ip)
    render_dict['comments'] = [] + list(hostobj.comments.all())

    addresses = hostobj.ipaddress_set.all()
    iphosts = hostobj.iphostname_set.all()

    results = []

    render_dict['entries'] = dict()

    for ip in set(addresses):
        render_dict['entries'][ip] = dict()
        render_dict['entries'][ip]['scans'] = []
        render_dict['entries'][ip]['vuln_total'] = 0
        render_dict['entries'][ip]['comments'] = ip.comments.all()
        if days_back != 0:
            dtime = datetime.now()-timedelta(days=days_back)
            results += ScanResults.objects.filter(ip=ip.ip, end__gte=dtime)
        else:
            results += ScanResults.objects.filter(ip=ip.ip)

    for iphost in iphosts:
        _ip = iphost.ip
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

                fpvulns = []
                for (x,y) in vulns:
                    z = False
                    r = FalsePositive.objects.filter(
                            Q(includes=_ip) | Q(include_all=True),
                            ~Q(excludes=_ip),
                            plugin__nessusid = y
                            )
                    if len(r) > 0:
                        z = True
                    fpvulns.append( (x,y,z) )

                #add the scan and its vulnerabilities to the rendering structure
                render_dict['entries'][iphost.ip]['scans'].append( ( scan, fpvulns ) )

    render_dict['comments'] = sorted(render_dict['comments'], key=lambda(x): x.modified, reverse=True)

    return render_dict

@login_required
def mac_view_core(request, mac, days_back):
    render_dict = {'pagetitle': 'Devices', 'subtitle': 'MAC Address'}
    render_dict['category'] = 'IP'
    render_dict['entry'] = mac
    render_dict['gator_info'] = gatorlink.Gator(mac)

    try:
        macobj = Mac.objects.get(mac=mac)
    except:
        return -1

    current_ip = macobj.macip_set.latest().ip.ip
    render_dict['most_frequent_user'] = get_most_frequent_user(current_ip)

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
        if days_back == 0:
            results = list(ScanResults.objects.filter(ip=ip))
        else:
            results = list(ScanResults.objects.filter(ip=ip, end__gte=dtime))

        for scan in results:
            if nice_ip not in render_dict['entries'].keys():
                render_dict['entries'][nice_ip] = {'scans': [], 'vuln_total': 0, 'name': nice_ip}
            if scan.vulns:
                vulns = scan.vulns.split(',')
                render_dict['entries'][nice_ip]['vuln_total'] += len(vulns)
                vulns = [i.split('|') for i in vulns]
            else:
                vulns = []

            fpvulns = []
            for (x,y) in vulns:
                z = False
                r = FalsePositive.objects.filter(
                        Q(includes=_ip) | Q(include_all=True),
                        ~Q(excludes=_ip),
                        plugin__nessusid = y
                        )
                if len(r) > 0:
                    z = True
                fpvulns.append( (x,y,z) )

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

    render_dict['comments'] = sorted(render_dict['comments'], key=lambda(x): x.modified, reverse=True)
    
    return render_dict


