from django.template import Library

register = Library()

@register.filter
def hash(h,key):
    return h[key]

@register.filter
def nrange(x, s=None):
    if s:
        return range(0,x,s)
    return range(x)
