from datetime import *
from django.http import *
from django.shortcuts import render_to_response
from django.db import *
from django.db.models import Q
from django.core.exceptions import *
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required, permission_required
from django.template import RequestContext
from falsepositives.models import *
from plugins.models import *
from utils.bobdb import *
from utils.djangolist import *
from utils.permissionutils import *
from utils import gatorlink

@login_required
def fp_view(request, fp_id):
    render_dict = {'pagetitle': 'False Positives', 'subtitle': 'Details'}

    fp = FalsePositive.objects.get(id=fp_id)
    
    render_dict['fp'] = fp
    render_dict['plugin'] = fp.plugin

    return render_to_response('false_positive.html', render_dict, context_instance=RequestContext(request))

@permission_required('sarimui.add_falsepositive')
def fp_create(request, pid):
    #Not using a render dict here because this will return a redirect to the modify page
    newfp = FalsePositive()
    newfp.user = request.user
    newfp.comment = 'Added from Plugin page'
    newfp.active = True
    newfp.plugin = Plugin.objects.get(id=pid)
    newfp.save()
    return HttpResponseRedirect( reverse( 'fp_modify', args=[newfp.id] ) )

@login_required
def fp_create_help(request):
    render_dict = {'pagetitle': 'False Positives', 'subtitle': 'Create'}
    return render_to_response('fp_create_help.html', render_dict, context_instance=RequestContext(request))

@permission_required('sarimui.delete_falsepositive')
def fp_delete(request, fp):
    FalsePositive.objects.get(id=int(fp)).delete()
    return HttpResponseRedirect(reverse('fp_search'))

@permission_required('sarimui.change_falsepositive')
def fp_modify(request, fp_id):
    render_dict = {'pagetitle': 'False Positives', 'subtitle': 'Modify'}

    fp = FalsePositive.objects.get(id=fp_id)

    render_dict['fp'] = fp
    render_dict['plugin'] = fp.plugin

    return render_to_response('fp_modify.html', render_dict, context_instance=RequestContext(request))

@login_required
def fp_search(request):
    render_dict = {'pagetitle':'False Positives', 'subtitle':'Search'}
    render_dict['category'] = "False Positive"

    if 'q' in request.GET.keys():
        search_term = request.GET['q']
        render_dict['search_term'] = search_term

        search_in = 'includes'
        if 'in' in request.GET.keys():
            if request.GET['in'].lower() == 'ex':
                search_in = 'excludes'

        ipobj = None
        if SARIMUI_SHORT_IP_RE.match(search_term):
            ipobj = IpAddress.objects.get(ip = aton('129.57.' + search_term))
        elif SARIMUI_IP_RE.match(search_term):
            ipobj = IpAddress.objects.get(ip = aton(search_term))
        else:
            fplist = FalsePositive.objects.all()

        if ipobj:
            if search_in == 'includes':
                fplist = ipobj.included_fp.all()
            elif search_in == 'excludes':
                fplist = ipobj.excluded_fp.all()
    else:
        fplist = FalsePositive.objects.all()

    result_list = []

    if len(fplist) > 1:
        for f in fplist:
            p = f.plugin
            result_list.append( {
                'url': reverse('fp_detail', args=[f.id]),
                'summary': p.name + ' - ' + p.summary,
                'description': 'Nessus ID %d' % p.nessusid
                } )
    elif len(fplist) == 1:
        return HttpResponseRedirect(reverse('fp_detail',args=[fplist[0].id]))

    render_dict['results'] = result_list

    return render_to_response('fp_search.html', render_dict, context_instance=RequestContext(request))
