import os, sys
projdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [projdir] + sys.path
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'



