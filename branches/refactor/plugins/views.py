from datetime import *
from django.http import *
from django.shortcuts import render_to_response
from django.db import *
from django.db.models import Q
from django.core.exceptions import *
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required, permission_required
from django.template import RequestContext
from plugins.models import *
from utils.bobdb import *
from utils.djangolist import *
from utils.permissionutils import *
from utils import gatorlink

@login_required
def plugin_view(request, plugin, version):
    render_dict = {}
    render_dict['plugin'] = plugin

    if version == 'latest':
        p = Plugin.objects.filter(nessusid=plugin).latest()
        render_dict['version'] = p.version
    else:
        render_dict['version'] = Plugin.objects.get(nessusid=plugin, version=version).latest().version

    return render_to_response("plugins/plugin.html", render_dict, context_instance=RequestContext(request))

@login_required
def plugin_list_view(request, plugin):
    return HttpResponse("List of things with this vulnerability found, part of the scan, etc goes here")

@login_required
def plugin_info_view(request, plugin, version):
    render_dict = {'pagetitle': 'Plugins', 'subtitle': 'Details'}
    render_dict['versions'] = []

    p_all = Plugin.objects.filter(nessusid=plugin)
    for plug in p_all:
        render_dict['versions'].append(plug.version)
    try:
        if version.lower() == 'latest':
            p = Plugin.objects.filter(nessusid=plugin).latest()
        else:
            p = Plugin.objects.get(nessusid=plugin, version=version)
    except ObjectDoesNotExist:
        render_dict['errormessage'] = "Invalid version selected, defaulting to latest"
        p = Plugin.objects.filter(nessusid=plugin).latest()

    render_dict['plugin'] = p
    render_dict['cve_list'] = [i.strip() for i in p.cveid.split(',')]
    render_dict['bid_list'] = [i.strip() for i in p.bugtraqid.split(',')]

    if 'noxref' not in p.xref.lower():
        render_dict['xref_list'] = []
        xref_list = [i.strip() for i in p.xref.split(',')]
        for xref in xref_list:
            (type, id) = xref.split(':',1)
            if 'OSVDB' in type:
                href = 'http://osvdb.org/show/osvdb/' + id
                render_dict['xref_list'].append( (type, id, href) )
            if 'RHSA' in type:
                rhsaid = '%s-%s' % (id[:9], id[10:13])
                href = 'http://rhn.redhat.com/errata/%s.html' % rhsaid
                render_dict['xref_list'].append( (type, id, href) )

    #get everything ready to work on
    desc = p.description
    ldesc = desc.lower()
    index = []
    #words to look for
    words = ['synopsis','description','solution','risk factor']
    #build a list of tuples of format (<word position>, <word>)
    for word in words:
        try:
            index.append( (ldesc.index(word), word) )
        except:
            index.append( (-1, word) )
    #sort the aforementioned list according to word position
    import operator
    sindex = sorted(index, key=operator.itemgetter(0))

    for pos, word in sindex:
        #Get the tuple's position in the list of tuples
        mappos = sindex.index( (pos, word) )
        #-1 means the word wasn't found...
        if pos == -1:
            #All this does is go find the next word without a -1 position
            #and copy all of the text from the start of the description to the
            #first position found
            if word == 'description':
                x = -1
                for i in range(mappos,len(sindex)):
                    if sindex[i][0] != -1:
                        x = sindex[i][0]
                s = desc[0:x]
            else:
                continue
        else:
            if mappos == len(sindex)-1:
                s = desc[pos+len(word):]
            else:
                s = desc[pos+len(word):sindex[mappos+1][0]]

        #The nessus plugin info has some stupid escaping going on
        s = s.replace(':\\n\\n', '')
        s = s.replace('\\n', ' ')
        s = s.replace(': ', '', 1)
        #Take care of dictionary names with spaces in them
        render_dict[word.replace(' ', '')] = s

    return render_to_response('plugins/plugin_info.html', render_dict, context_instance=RequestContext(request))

@login_required
def plugin_search(request):
    render_dict = {'pagetitle': 'Plugins', 'subtitle': 'Search'}
    render_dict['category'] = "Plugin"
    render_dict['search_header'] = "Enter a Nessus ID"
    what = ''
    for i in request.GET.keys():
        if i.lower() == 'q':
            what = request.GET[i]
            break
    else:
        return render_to_response('search.html',render_dict, context_instance=RequestContext(request))

    try:
        Plugin.objects.filter(nessusid=int(what)).latest()
        return HttpResponseRedirect(reverse('plugin', args=[what, 'latest']))
    except:
        render_dict['errors'] = ["No plugin with Nessus ID " + str(what) + " found.",]
        return render_to_response('search.html', render_dict, context_instance=RequestContext(request))
