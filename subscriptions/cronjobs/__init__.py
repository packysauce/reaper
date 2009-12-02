from devices.models import *
from vulnerabilities.models import *
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.db.models import F
from django.template.loader import render_to_string
from utils.gatorlink import *
from django.conf import settings
from django.core import mail
import datetime as dt

def get_vulns_in_vlan(vlan, days_back):
    """Gets all the vulnerabilities in a vlan"""
    import ipaddr

    network = ipaddr.IPNetwork(vlan.network)
    start_ipn = int(network[0])
    end_ipn = int(network[-1])
    delta = dt.datetime.now() - dt.timedelta(days=days_back)
    
    results = {} # {ip: (vuln, vuln, vuln)}
    for i in ScanResults.objects.filter(ip__range=[start_ipn, end_ipn], vulns__isnull=False, end__gte=delta).order_by('ip'):
        if results.has_key(i.ip):
            results[i.ip].append(i)
        else:
            results[i.ip] = [i,]

    return results

def get_ip_vulns(user, days_back):
    """Gets the vulnerabilities for all the User's subscribed IPs"""
    ips = [i.content_object.ip for i in user.subscriptions.filter(content_type=ContentType.objects.get_for_model(IpAddress))]
    delta = dt.datetime.now() - dt.timedelta(days=days_back)

    results = {}
    for i in ScanResults.objects.filter(ip__in=ips, vulns__isnull=False, end__gte=delta):
        if results.has_key(i.ip):
            results[i.ip].append(i)
        else:
            results[i.ip] = [i,]

    return results

def get_mac_vulns(user, days_back):
    """Gets the vulnerabilities for all the User's subscribed MACs"""
    #get subscribed hosts
    sub_macs = [i.content_object for i in user.subscriptions.filter(content_type=ContentType.objects.get_for_model(Mac))]
    delta = dt.datetime.now() - dt.timedelta(days=days_back)

    results = {}
    for mac in sub_macs:
        ips = [i.ip.ip for i in mac.macip_set.filter(entered__gte=delta)]
        tmp = list(ScanResults.objects.filter(ip__in=ips, vulns__isnull=False, end__gte=delta))
        if len(tmp) == 0:
            continue
        if results.has_key(mac):
            results[mac] += tmp
        else:
            results[mac] = tmp

    return results

def get_host_vulns(user, days_back):
    """Gets the vulnerabilities for all the User's subscribed Hostnames"""
    sub_hosts = [i.content_object for i in user.subscriptions.filter(content_type=ContentType.objects.get_for_model(Hostname))]
    owned_hosts = get_hosts_by_user(user.username)
    diff_hosts = [i for i in owned_hosts if i not in sub_hosts]
    sub_hosts += list(Hostname.objects.filter(hostname__in=diff_hosts))
            
    delta = dt.datetime.now() - dt.timedelta(days=days_back)

    results = {}
    for host in sub_hosts:
        ips = [i.ip.ip for i in host.iphostname_set.filter(entered__gte=delta)]
        tmp = list(ScanResults.objects.filter(ip__in=ips, vulns__isnull=False, end__gte=delta))
        if len(tmp) == 0:
            continue
        if results.has_key(host):
            results[host] += tmp
        else:
            results[host] = tmp

    return results
    
def assemble_email(user, days_back=7):
    """Returns the email report for the user's susbscribed devices"""

    render_dict = {'SITE_URL': settings.SITE_URL}
    
    ip_vulns = get_ip_vulns(user, days_back)
    mac_vulns = get_mac_vulns(user, days_back)
    host_vulns = get_host_vulns(user, days_back)

    vlan_vulns = {}
    for v in [i.content_object for i in user.subscriptions.filter(content_type=ContentType.objects.get_for_model(Vlan))]:
        vlan_vulns[v.vlan_id] = get_vulns_in_vlan(v, days_back)

    render_dict['machines'] = ip_vulns.copy()
    render_dict['machines'].update(mac_vulns)
    render_dict['machines'].update(host_vulns)
    render_dict['vlans'] = vlan_vulns
    render_dict['days_back'] = days_back

    return render_to_string('email/wrapper.html', render_dict)

def debug_email_user(user, to, days_back=7):
    msg = mail.EmailMessage("SARIM Subscribed Vulnerabilities", assemble_email(user, days_back), settings.EMAIL_FROM, (to,))
    msg.content_subtype = "html"
    msg.send()

def email_user(user, days_back=7):
    msg = mail.EmailMessage("SARIM Subscribed Vulnerabilities", assemble_email(user, days_back), settings.EMAIL_FROM, (user.email,))
    msg.content_subtype = "html"
    msg.send()

def email_users(days_back=7):
    messages = []
    for user in User.objects.filter(is_staff=True, email__isnull=False):
        msg = mail.EmailMessage("SARIM Subscribed Vulnerabilities", assemble_email(user, days_back), settings.EMAIL_FROM, (user.email,))
        msg.content_subtype = "html"
        messages.append(msg)

    cx = mail.get_connection()
    cx.send_message(messages)
    
