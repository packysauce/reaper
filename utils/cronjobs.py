import os, sys
import ipaddr

#Find out where we are!
projdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [projdir] + sys.path
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from devices.models import Vlan, VlanDump


dump = VlanDump.objects.latest()

#Get the 4 parts of a vlan record entry
for subnet,mask,vlan,purpose in map(lambda x: x.split(';'), dump.record.split(';;'))[1:]:
    vlanobj, created = Vlan.objects.get_or_create(vlan_id=vlan)
    #Just created a new vlan obj, set other stuffs
    net = ipaddr.IPNetwork("{0}/{1}".format(subnet,mask))
    if created:
        vlanobj.network = str(net)
        vlanobj.purpose = purpose
        vlanobj.save()
    else:
        if vlanobj.network != str(net):
            vlanobj.network = str(net)
            vlanobj.purpose = purpose

