from django.http import *
from django.shortcuts import *
from django.template import RequestContext
from django.contrib.auth.decorators import user_passes_test
from subscriptions.models import *
from subscriptions import ajax
from devices.models import *

# Create your views here.
@user_passes_test(lambda x: x.is_staff)
def edit_subscriptions(request):
    render_dict = { 'pagetitle': 'Preferences', 'subtitle': 'Subscriptions' }
    if request.POST:
        if not ajax.modify_vlan_subs(request):
            render_dict['vlan_msg_type'] = "error"
            render_dict['vlan_msg'] = 'Unable to save VLAN subscriptions'
        else:
            render_dict['vlan_msg_type'] = 'success'
            render_dict['vlan_msg'] = 'VLAN subscriptions saved!'

    get_subs = request.user.subscriptions.filter
    render_dict['subscribed_ips'] = get_subs(content_type=ContentType.objects.get_for_model(IpAddress))
    render_dict['subscribed_hosts'] = get_subs(content_type=ContentType.objects.get_for_model(Hostname))
    render_dict['subscribed_macs'] = get_subs(content_type=ContentType.objects.get_for_model(Mac))
    render_dict['vlans'] = Vlan.objects.all()
    return render_to_response('edit_subscr.html', render_dict, context_instance=RequestContext(request))

@user_passes_test(lambda x: x.is_staff)
def edit_subscriptions_new(request):
    render_dict = {'pagetitle': 'Preferences', 'subtitle': 'Subscriptions' }
