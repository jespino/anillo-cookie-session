from anillo.http.responses import Response
from anillo.http.request import Request

from anillo_cookie_session.backends import BaseCookieStorage, InsecureJsonCookieStorage, JWSCookieStorage, _SessionKey
from unittest import mock

class DummyCookieStorage(BaseCookieStorage):
    def loads(self, data):
        return data[0]

    def dumps(self, data):
        return [data]

def test_base_cookie_storage_without_session():
    storage = DummyCookieStorage()
    request = Request()
    session_key = storage.get_session_key(request)
    assert session_key.get() is None

def test_base_cookie_storage_with_session():
    storage = DummyCookieStorage()
    request = Request()
    request.cookies = {"session-id": {"value": ["test"]}}
    session_key = storage.get_session_key(request)
    assert session_key.get() == ["test"]

def test_base_cookie_storage_with_custom_cookie_name_session():
    storage = DummyCookieStorage("session")
    request = Request()
    request.cookies = {"session-id": {"value": ["test"]}}
    session_key = storage.get_session_key(request)
    assert session_key.get() == None

    request.cookies = {"session": {"value": ["test"]}}
    session_key = storage.get_session_key(request)
    assert session_key.get() == ["test"]

def test_base_cookie_storage_persist_session_without_cookies():
    storage = DummyCookieStorage()
    request = Request()
    response = Response()
    storage.persist_session_key(request, response, _SessionKey(100))
    assert response.cookies['session-id']['value'] == 100

def test_base_cookie_storage_persist_session_with_cookies():
    storage = DummyCookieStorage()
    request = Request()
    response = Response()
    response.cookies = {}
    storage.persist_session_key(request, response, _SessionKey(100))
    assert response.cookies['session-id']['value'] == 100

def test_base_cookie_storage_persist_session_without_changing_the_session_key():
    storage = DummyCookieStorage()
    request = Request()
    request.cookies = {"session-id": {"value": ["test"]}}
    response = Response()
    response.cookies = {}
    storage.persist_session_key(request, response, _SessionKey(100))
    assert response.cookies['session-id']['value'] == 100

    request.cookies = response.cookies
    response.cookies = {}
    storage.persist_session_key(request, response, _SessionKey(100))
    assert response.cookies == {}

def test_base_cookie_storage_store_retrieve():
    storage = DummyCookieStorage()
    request = Request()
    response = Response()

    data = {"test": "test"}
    session_key = _SessionKey("test-session")

    storage.store(request, response, session_key, data)
    retrieved_data = storage.retrieve(request, session_key)
    assert data == retrieved_data

def test_insecure_json_cookie_storage_store_retrieve():
    storage = InsecureJsonCookieStorage()

    data = {"test": "test"}

    assert storage.dumps(data) != data
    assert storage.loads(storage.dumps(data)) == data

def test_jws_cookie_storage_store_retrieve():
    storage = JWSCookieStorage("secret")

    data = {"test": "test"}

    assert storage.dumps(data) != data
    assert storage.loads(storage.dumps(data)) == data
