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

def new_ip_view(request, ip):
    #first, gather all the scans with the IP
    #second, gather all the MAC associations with the IP
    #third, look at the MAC assoc. between the scan start and end times to see
    #        what MAC a particular IP was using at the time

    scanresults = ScanResults.objects.filter(ip=aton(ip), state='up')
    scans = set([i.scanrun for i in scanresults])
    associations = MacIp.objects.filter(ip=aton(ip))

    #set up a dictionary of lists, where the dictionary holds the MACs
    # and the list holds all the scan results
    arranged_scans = dict()
    assoc_set = set([i.macid.mac for i in associations])
    for mac in assoc_set:
        arranged_scans[mac] = []

    for assoc in associations:
        for scan in scanresults:
            if (scan.end >= assoc.observed) and (scan.end <= assoc.entered):
                arranged_scans[assoc.macid.mac].append(scan)

    tmp_dict = dict()
    tmp_dict['scans_by_mac'] = arranged_scans
    tmp_dict['ip'] = ip

    return render_to_response('new_ip.html', tmp_dict)

def ip_view(request,ip):
    tmp_dict = dict() #comments, macs, scans
    tmp_dict['comments'] = IpComments.objects.filter(ip=aton(ip))
    tmp_dict['macs'] = set([ i.macid for i in MacIp.objects.filter(ip=aton(ip))])
    tmp_dict['ip'] = ip

    scanresults = ScanResults.objects.filter(ip=aton(ip))
    resultsdict = dict()

    for scan in scanresults:
        try:
            resultsdict[scan.scanrun.id].append(scan)
        except:
            resultsdict[scan.scanrun.id] = []
            resultsdict[scan.scanrun.id].append(scan)

    tmp_dict['scans'] = scanresults


    #So now we have to decide what subnet an IP is in
    # then take that subnet and grab the related host sets
    # then take the host set and grab the related scans
    hostsets = []
    for i in HostSet.objects.all():
        (subnet, bits) = i.name.split('-')
        subnet_parts = subnet.split('.')

        #doing 2 here first to short circuit as much as possible
        if len(subnet_parts) == 2:
            subnet = '.'.join(['129.57']+subnet_parts) + '/' + bits
        elif len(subnet_parts) == 4:
            subnet = subnet + '/' + bits
        elif len(subnet_parts) == 3:
            subnet = '.'.join(['129']+subnet_parts) + '/' + bits

        try:
            if ip in ipcalc.Network(subnet):
                if aton(ip) in i.iplist:
                    hostsets.append(i)
        except:
            continue

    return render_to_response('ip.html', tmp_dict)
