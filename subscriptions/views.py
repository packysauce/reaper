from django.http import *
from django.shortcuts import *
from django.template import RequestContext
from subscriptions.models import *
from devices.models import *

# Create your views here.
def edit_subscriptions(request):
    render_dict = { 'pagetitle': 'Preferences', 'subtitle': 'Subscriptions' }
    get_subs = request.user.subscriptions.filter
    render_dict['subscribed_ips'] = get_subs(content_type=ContentType.objects.get_for_model(IpAddress))
    render_dict['subscribed_hosts'] = get_subs(content_type=ContentType.objects.get_for_model(Hostname))
    render_dict['subscribed_macs'] = get_subs(content_type=ContentType.objects.get_for_model(Mac))
    return render_to_response('edit_subscr.html', render_dict, context_instance=RequestContext(request))
