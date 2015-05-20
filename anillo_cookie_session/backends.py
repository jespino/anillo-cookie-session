import json

from itsdangerous import JSONWebSignatureSerializer


class _SessionKey:
    def __init__(self, value):
        self.value = value

    def set(self, value):
        self.value = value

    def get(self):
        return self.value


class BaseCookieStorage:
    def __init__(self, cookie_name="session-id"):
        self.cookie_name = cookie_name

    def get_session_key(self, request):
        return _SessionKey(request.get('cookies', {}).get(self.cookie_name, {}).get('value', None))

    def persist_session_key(self, request, response, session_key):
        if request.get("cookies", {}).get(self.cookie_name, {}).get('value', None) != session_key.get():
            if not hasattr(response, 'cookies'):
                response.cookies = {}
            response.cookies[self.cookie_name] = {"value": session_key.get()}

    def store(self, request, response, session_key, data):
        session_key.set(self.dumps(data))

    def retrieve(self, request, session_key):
        try:
            print(self.loads(session_key.get()))
            return self.loads(session_key.get())
        except Exception:
            return {}


class InsecureJsonCookieStorage(BaseCookieStorage):
    def dumps(self, data):
        return json.dumps(data)

    def loads(self, data):
        return json.loads(data)


class JWSCookieStorage(BaseCookieStorage):
    def __init__(self, secret, cookie_name="session-id"):
        self.cookie_name = cookie_name
        self.serializer = JSONWebSignatureSerializer(secret)

    def dumps(self, data):
        return self.serializer.dumps(data)

    def loads(self, data):
        return self.serializer.loads(data)
