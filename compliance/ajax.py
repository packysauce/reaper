from django.http import *
from django.shortcuts import render_to_response
from django.template import RequestContext
from compliance.models import *
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.core.urlresolvers import reverse
import datetime as dt
import django.utils.simplejson as json
import pprint as pp
import sha

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
        new_policy.hash = sha.sha(data).hexdigest()
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
