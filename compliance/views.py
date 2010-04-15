from django.http import *
from django.shortcuts import render_to_response
from django.template import RequestContext
from compliance.models import *
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
import datetime as dt

# Create your views here.
@user_passes_test(lambda u: u.is_staff == 1)
def index(request):
    days_back = request.user.get_profile().default_days_back

    render_dict = {
            'pagetitle': 'Compliance',
            'results': Result.objects.all(),
            #'results': Result.objects.filter( scan__stop__gte = dt.date.today() - dt.timedelta(days=7) ),
            }

    return render_to_response('compliance_results.html', render_dict, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff == 1)
def policy_manager(request):
    #need upload, download, view all policies
    render_dict = {
            'pagetitle': 'Compliance',
            'subtitle': 'Policies',
            'policy_types': Policy.TYPE_CHOICES,
            'policies': Policy.objects.all().order_by('-timestamp', 'name'),
            }

    return render_to_response('compliance_policies.html', render_dict, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff == 1)
def scan_manager(request):
    render_dict = {
            'pagetitle': 'Compliance',
            'subtitle': 'Scans',
            'scans': Scan.objects.all(),
            }

    return render_to_response('compliance_scans.html', render_dict, context_instance=RequestContext(request))
