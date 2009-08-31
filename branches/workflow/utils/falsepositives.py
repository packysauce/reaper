from sarimui.models import *
from utils.bobdb import *
from utils.djangolist import *

class FalsePositivesHelper(object):
    def __init__(self, ip=None, plugin=None):
        """Initializes the class with the requested data. If 'ip' is specified, then load only that IP's FP data.
        If plugin is specified, then load only that plugin's data.
        If neither are specified, load all the FalsePositive data.
        """
        self.__fplist = []

        #grab all of the false positives for the required criteria
        if ip == None and plugin == None:
            self.__fplist = list(FalsePositive.objects.filter(active=True))
        elif plugin != None and ip == None:
            self.__fplist = list(FalsePositive.objects.filter(nessusid=int(plugin),active=True))
        elif ip != None and plugin == None:
            self.__fplist = list(FalsePositive.objects.filter(ip=anyton(ip),active=True))
        else:
            self.__fplist = list(FalsePositive.objects.filter(ip=anyton(ip), nessusid=int(plugin),active=True))

        return

    def __in_iplist(self, ip, fplist):
        fplistlower = fplist.lower()
        if "all" in fplistlower:
            return True
        if "none" in fplistlower:
            return False
        
        if ip in fplist.split(','):
            return True

        return False

    def is_falsepositive(self, ip, nessusid):
        """Checks the ip and nessusid combination against the data loaded to see if it is a false positive.
        """
        if type(ip) == int or type(ip) == str:
            _ip = anytoa(ip)
        elif type(ip) == ScanResult:
            _ip = ScanResult.ip_id
        else:
            raise ValueError("Must specify IP as a number, string, or ScanResult")

        fpidx = get_index_by_attr(self.__fplist, "nessusid_id", long(nessusid))
        if fpidx == -1:
            return False

        curfp = self.__fplist[fpidx]
        ip_excluded = False
        nessusid_invalid = False

        #if the date's OK and the IP is in the lists, it's a false positive!
        if curfp.date_added > Plugin.objects.filter(nessusid=curfp.nessusid_id).latest().entered:
            if self.__in_iplist(_ip, curfp.includes) and not self.__in_iplist(_ip, curfp.excludes):
                return True

        #current FP is older than the newest version of the plugin
        # or the ip is not included in the false positive
        # or the ip is specifically excluded from the false positive
        return False
