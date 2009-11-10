from django.http import *
from django.shortcuts import *
from django.template import RequestContext
from subscriptions.models import *
from devices.models import *

# Create your views here.
def edit_subscriptions(request):
    render_dict = { 'pagetitle': 'Preferences', 'subtitle': 'Subscriptions' }
    return render_to_response('edit_subscr.html', render_dict, context_instance=RequestContext(request))
