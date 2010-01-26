from datetime import *
from django.http import *
from django.shortcuts import render_to_response
from django.db import *
from django.db.models import Q
from django.core.exceptions import *
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required, permission_required
from django.template import RequestContext
from scans.models import *
from vulnerabilities.models import ScanResults
from devices.models import *
from utils.bobdb import *
from utils.djangolist import *
from utils.permissionutils import *
from utils import gatorlink

@login_required
def scan_view(request, scan):
    render_dict = {'pagetitle': 'Scans', 'subtitle': 'Details'}
    render_dict['id'] = scan
    try:
        scanobj = ScanRun.objects.get(id=scan)
    except:
        return render_to_response('scans/scan_view.html', render_dict, context_instance=RequestContext(request))

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

    return render_to_response('scan_view.html', render_dict, context_instance=RequestContext(request))

@login_required
def scan_search(request):
    render_dict = {'pagetitle': 'Scans', 'subtitle': 'Search'}
    render_dict['category'] = "Scan"
    render_dict['search_header'] = "Enter a Scan ID"
    render_dict['results'] = []
    results = ScanRun.objects.filter( end__gte = date.today() - timedelta(days=7) ).order_by('-end')

    for r in results:
        render_dict['results'].append( {'url':reverse('scan', args=[r.id]), 'description': r.end, 'summary': r.id })

    what = ''
    for i in request.GET.keys():
        if i.lower() == 'q':
            what = request.GET[i]
            break
    else:
        return render_to_response('search.html',render_dict, context_instance=RequestContext(request))

    try:
        ScanRun.objects.get(id=what)
    except:
        render_dict['errors'] = ["No scan with ID " + str(what) + " found.",]
        return render_to_response('search.html', render_dict)

    return HttpResponseRedirect(reverse('scan', args=[what]))


