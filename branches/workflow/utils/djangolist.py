# $Date$
# $Author$
# $Rev$
# $URL$
# $Id$
"""Helper functions to assist in manipulating lists of Django models
"""

def get_index_by_attr(djlist, attrname, searchfor):
    """Searches the given list for a particular value of a particular attribute
    and returns the index of the first match.
    """
    if djlist == None or type(djlist) != list:
        raise ValueError("First positional argument must be a list")
    if attrname == None or type(attrname) != str:
        raise ValueError("Second positional argument must be the attribute name")
    if searchfor == None:
        raise ValueError("Third positional argument must be what to search for")

    for i in range(0,len(djlist)):
        if djlist[i].__dict__[attrname] == searchfor:
            return i

    return -1

def get_indices_by_attr(djlist, attrname, searchfor):
    """Searches the given list for a particular value of a particular attribute
    and returns a list of indices of matches.
    """
    if djlist == None or type(djlist) != list:
        raise ValueError("First positional argument must be a list")
    if attrname == None or type(attrname) != str:
        raise ValueError("Second positional argument must be the attribute name")
    if searchfor == None:
        raise ValueError("Third positional argument must be what to search for")

    rlist = []

    for i in range(0,len(djlist)-1):
        if djlist[i].__dict__[attrname] == searchfor:
            rlist.append(i)

    return rlist
