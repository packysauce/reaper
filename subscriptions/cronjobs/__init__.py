from devices.models import *
from vulnerabilities.models import *

def get_vulns_in_vlan(vlan, days_back):
    import ipaddr
    import datetime as dt

    network = ipaddr.IPNetwork(vlan.network)
    start_ipn = int(network[0])
    end_ipn = int(network[-1])
    delta = dt.datetime.now() - dt.timedelta(days=days_back)

    return ScanResults.objects.filter(ip__range=[start_ipn, end_ipn], vulns__isnull=False, end__gte=delta)
