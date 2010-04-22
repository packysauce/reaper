from django.http import *
from django.shortcuts import render_to_response
from django.template import RequestContext
from compliance.models import *
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
import datetime as dt
from django.core.urlresolvers import reverse

# Create your views here.
@user_passes_test(lambda u: u.is_staff == 1)
def index(request):
    days_back = request.user.get_profile().default_days_back

    render_dict = {
            'pagetitle': 'Compliance',
            'results': Result.objects.all() #.order_by('-scan__stop'),
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
            'scans': Scan.objects.all().order_by('-stop'),
            }

    return render_to_response('compliance_scans.html', render_dict, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff == 1)
def create_scan_schedule(request):
    day_on = lambda x: request.POST.has_key(x) and request.POST[x] == 'on'
    try:
        name = request.POST['name']
        m = day_on('mon')
        t = day_on('tue')
        w = day_on('wed')
        th = day_on('thu')
        fr = day_on('fri')
        sa = day_on('sat')
        su = day_on('sun')
        hour = request.POST['hour']
        minute = request.POST['minute']
        if int(hour) not in range(24):
            raise ValueError('Hour out of range')
        if int(minute) not in range(60):
            raise ValueError('Minute out of range')
        if not (m or t or w or th or fr or sa or su):
            raise ValueError('At least one day must be checked')
    except Exception, e:
        request.user.message_set.create(message='Unable to schedule scan: %s' % str(e))
        return HttpResponseRedirect( reverse('compliance_scan_schedule') )
    
    zf = lambda x: str.zfill(str(x), 2)
    scan_schedule = ScheduledScan()
    scan_schedule.time = "%s:%s:00" % (zf(hour), zf(minute))
    scan_schedule.monday = m
    scan_schedule.tuesday = t
    scan_schedule.wednesday = w
    scan_schedule.thursday = th
    scan_schedule.friday = fr
    scan_schedule.saturday = sa
    scan_schedule.sunday = su
    scan_schedule.name = name
    scan_schedule.save()

    request.user.message_set.create(message='Scheduled successfully!')
    return HttpResponseRedirect( reverse('compliance_scan_schedule') )

@user_passes_test(lambda u: u.is_staff == 1)
def scan_schedules(request):
    render_dict = {
            'pagetitle': 'Compliance',
            'subtitle': 'Scans',
            'schedules': ScheduledScan.objects.all().order_by('name'),
            }

    return render_to_response('compliance_scan_schedule.html', render_dict, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff == 1)
def scan_configurations(request):
    render_dict = {
            'pagetitle': 'Compliance',
            'subtitle': 'Scans',
            }

    return render_to_response('compliance_scan_configurations.html', render_dict, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff == 1)
def scan_targets(request):
    render_dict = {
            'pagetitle': 'Compliance',
            'subtitle': 'Scans',
            'targets': Target.objects.all(),
            }

    return render_to_response('compliance_scan_targets.html', render_dict, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff == 1)
def scan_templates(request):
    render_dict = {
            'pagetitle': 'Compliance',
            'subtitle': 'Scans',
            'templates': Template.objects.all(),
            }

    return render_to_response('compliance_scan_templates.html', render_dict, context_instance=RequestContext(request))
