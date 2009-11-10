
class DummyUsernameMiddleware(object):
    def process_request(self, request):
        try:
            request.META["REMOTE_USER"]
        except:
            request.META["REMOTE_USER"] = 'pdwhite'
