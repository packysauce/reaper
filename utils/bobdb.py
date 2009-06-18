
def aton(address):
    bits = [int(i) for i in address.split('.')]
    return int("%02x%02x%02x%02x" % (bits[0],bits[1],bits[2],bits[3]),16)

def ntoa(value):
    string = "%08x" % value
    return '.'.join(["%d" % int(string[i]+string[i+1],16) for i in range(0,8,2)])

