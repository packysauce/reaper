from django.http import *
from django.shortcuts import render_to_response
from django.template import RequestContext
from compliance.models import *
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.core.urlresolvers import reverse
import datetime as dt
import django.utils.simplejson as json
import pprint as pp
import re
import sha

def hash(data):
    return sha.sha(data).hexdigest()

@user_passes_test(lambda u: u.is_staff == 1)
def upload_policy(request):
    if not request.FILES:
        return HttpResponse( json.dumps( {'result': 'failure'} ) )

    data = request.FILES['file'].read()
    
    try:
        new_policy = Policy()
        new_policy.name = request.POST['filename']
        new_policy.data = data
        new_policy.type = request.POST['type']
        new_policy.hash = hash(data) 
        new_policy.save()
        request.user.message_set.create(message="Uploaded successfully")
        return HttpResponseRedirect( reverse('compliance_policies') )
    except Exception, e:
        request.user.message_set.create(message='Upload failed: %s' % str(e))
        return HttpResponseRedirect( reverse('compliance_policies') )

@user_passes_test(lambda u: u.is_staff == 1)
def download_policy(request, policy_id):
    try:
        policy = Policy.objects.get(id=policy_id)
    except Exception, e:
        request.user.message_set.create(message='File not found')
        return HttpResponseRedirect( reverse('compliance_policies') )

    response = HttpResponse(policy.data, mimetype='text/plain')
    response['Content-Disposition'] = 'attachment; filename=%s' % policy.name
    return response

@user_passes_test(lambda u: u.is_staff == 1)
def delete_policy(request, policy_id):
    try:
        Policy.objects.get(id=policy_id).delete()
    except Exception, e:
        request.user.message_set.create(message='Error: %s' % str(e))
        return HttpResponseRedirect( reverse('compliance_policies') )

    return HttpResponseRedirect( reverse('compliance_policies') )

@user_passes_test(lambda u: u.is_staff == 1)
def create_targets(request):
    if not request.POST.has_key('targetdata') or not request.POST['targetdata']:
        request.user.message_set.create(message='You must include target data if you wish to make a new target')
        return HttpResponseRedirect( reverse('compliance_scan_targets') )
    if not request.POST.has_key('name') or not request.POST['name']:
        request.user.message_set.create(message='You must include a name for the new target')
        return HttpResponseRedirect( reverse('compliance_scan_targets') )
    try:
        target = Target()
        target.name = request.POST['name']
        target.targets = request.POST['targetdata']
        target.hash = hash(request.POST['targetdata'])
        target.save()
    except Exception, e:
        request.user.message_set.create(message='Unexpected error: %s' % str(e))

    return HttpResponseRedirect( reverse('compliance_scan_targets') )

@user_passes_test(lambda u: u.is_staff == 1)
def delete_targets(request, id):
    try:
        Target.objects.get(id=id).delete()
    except Exception, e:
        request.user.message_set.create(message='Error: %s' % str(e))
        return HttpResponseRedirect( reverse('compliance_scan_targets') )

    return HttpResponseRedirect( reverse('compliance_scan_targets') )

@user_passes_test(lambda u: u.is_staff == 1)
def create_template(request):
    if not request.POST.has_key('data') or not request.POST['data']:
        request.user.message_set.create(message='You must include template data if you wish to make a new template')
        return HttpResponseRedirect( reverse('compliance_scan_templates') )
    if not request.POST.has_key('name') or not request.POST['name']:
        request.user.message_set.create(message='You must include a name for the new template')
        return HttpResponseRedirect( reverse('compliance_scan_templates') )
    try:
        template = Template()
        template.name = request.POST['name']
        template.data = request.POST['data']
        template.hash = hash(request.POST['data'])
        template.save()
    except Exception, e:
        request.user.message_set.create(message='Unexpected error: %s' % str(e))

    return HttpResponseRedirect( reverse('compliance_scan_templates') )

@user_passes_test(lambda u: u.is_staff == 1)
def delete_template(request, id):
    try:
        Template.objects.get(id=id).delete()
    except Exception, e:
        request.user.message_set.create(message='Error: %s' % str(e))
        return HttpResponseRedirect( reverse('compliance_scan_templates') )

    return HttpResponseRedirect( reverse('compliance_scan_templates') )
