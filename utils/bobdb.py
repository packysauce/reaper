import re, ipaddr

SARIMUI_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
SARIMUI_SHORT_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}$")
SARIMUI_MAC_RE = re.compile(r"^([a-fA-F0-9]{2}:){5}([a-fA-F0-9]){2}$")

def ip_in_network(address, network):
    """Determines if an IP address is in the specified CIDR block.
    address and network can be in dotted-quad or numeric, but assumes a /32
    """
    return ipaddr.IPAddress(address) in ipaddr.IPNetwork(network)

def aton(address):
    """Support function to convert an IP address in dotted quad notation to a 32-bit integer
    """
    return int(ipaddr.IPAddress(address))

def ntoa(value):
    """Support function to convert a 32-bit integer to an IP address in dotted quad notation
    """
    return str(ipaddr.IPAddress(value))

def anyton(value):
    """Takes a string or int IP and returns the int IP form
    """
    if type(value) == long:
        return value
    if isinstance(value, basestring):
        return aton(value)

def anytoa(value):
    """Takes a string or int IP and returns the str IP form
    """
    if isinstance(value, basestring):
        return value
    if type(value) == long:
        return ntoa(value)

def get_most_frequent_user_list(ip = None):
    """Takes an ip address, queries 'secsys' and gets the most-occuring username
    """
    if ip == None:
        return None

    user = 'secsys_r'
    db = 'secsys'
    host = 'ccdevdb.jlab.org'
    password = 'SS-readonly'

    n_ip = anyton(ip)
    a_ip = anytoa(ip)

    query = "SELECT * FROM `loginhistory` WHERE `dsthost` = '%s' OR `srcip` = %d "
    query += "AND `date` > DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)"
    query = query % (a_ip, n_ip)

    import MySQLdb
    dbconn = MySQLdb.connect(user=user, host=host, db=db, passwd=password)
    c = dbconn.cursor()
    nresults = c.execute(query)
    results = c.fetchall()

    mfu = None
    if nresults != 0:
        namecounts = {}

        for i in results:
            if namecounts.has_key(i[4]):
                namecounts[i[4]] += 1
            else:
                namecounts[i[4]] = 1

        mfu = sorted(namecounts.items(), key=lambda(x): x[1], reverse=True)

    c.close()
    dbconn.close()
    return mfu

def get_most_frequent_user(ip = None):
    if ip == None:
        return None

    mful = get_most_frequent_user_list(ip)
    if mful == None:
        return None
    else:
        return mful[0][0]
