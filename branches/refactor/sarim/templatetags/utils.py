from django.template import Library

register = Library()

@register.filter
def hash(h,key):
    return h[key]

