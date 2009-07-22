import re

def aton(address):
    """Support function to convert an IP address in dotted quad notation to a 32-bit integer
    """
    if not isinstance(address, basestring):
        raise ValueError("Argument must be of type string or unicode")
    if not re.match("(\d{1,3}\.){3}\d{1,3}", address):
        raise ValueError("Argument must be in the format 'xxx.xxx.xxx.xxx'. IPv6 not supported")
    bits = [int(i) for i in address.split('.')]
    return int("%02x%02x%02x%02x" % (bits[0],bits[1],bits[2],bits[3]),16)

def ntoa(value):
    """Support function to convert a 32-bit integer to an IP address in dotted quad notation
    """
    if not isinstance(value, long):
        raise ValueError("Argument must be of type long")
    string = "%08x" % value
    return '.'.join(["%d" % int(string[i]+string[i+1],16) for i in range(0,8,2)])
