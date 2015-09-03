import json

from jwkest.jwk import SYMKey
from jwkest.jwe import JWE


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
    def __init__(self, secret, cookie_name="session-id", sign_alg="ES256"):
        self.cookie_name = cookie_name
        self.secret = secret
        self.sign_alg = sign_alg

    def dumps(self, data):
        sym_key = SYMKey(key=self.secret, alg=self.cypher_alg)
        jws = JWS(data, alg=self.sign_alg)
        return jws.sign_compact(keys=[self.secret])

    def loads(self, data):
        jws = JWS()
        return jws.verify_compact(data, keys=[self.secret])


class JWECookieStorage(BaseCookieStorage):
    def __init__(self, secret, cookie_name="session-id", cypher_alg="A128KW", cypher_enc="A256CBC-HS512"):
        self.cookie_name = cookie_name
        self.secret = secret
        self.cypher_alg = cypher_alg
        self.cypher_enc = cypher_enc
        self.sym_key = SYMKey(key=self.secret, alg=self.cypher_alg)

    def dumps(self, data):
        jwe = JWE(json.dumps(data), alg=self.cypher_alg, enc=self.cypher_enc)
        return jwe.encrypt([self.sym_key])

    def loads(self, data):
        (plain, success) = JWE().decrypt(data, keys=[self.sym_key])
        if success:
          return json.loads(plain.decode('utf-8'))
        return None
