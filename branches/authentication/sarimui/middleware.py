
class DummyUsernameMiddleware(object):
    def process_request(self, request):
        request.META["REMOTE_USER"] = 'pdwhite'
