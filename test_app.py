import json
import pytest  # type: ignore
import re

import app as multitrack_drafting


@pytest.fixture
def client():
    multitrack_drafting.app.testing = True
    client = multitrack_drafting.app.test_client()

    with client:
        yield client
    # request context stays alive until the fixture is closed

def test_csrf_token_generate():
    with multitrack_drafting.app.test_request_context():
        token = multitrack_drafting.csrf_token()
        assert token != ''


def test_csrf_token_save():
    with multitrack_drafting.app.test_request_context() as context:
        token = multitrack_drafting.csrf_token()
        assert token == context.session['csrf_token']


def test_csrf_token_load():
    with multitrack_drafting.app.test_request_context() as context:
        context.session['csrf_token'] = 'test token'
        assert multitrack_drafting.csrf_token() == 'test token'

class MockResponse:
    def get(action, meta=None, **kwargs):
        if action == 'wbgetentities':
            if kwargs['ids'] == 'Q123':
                # load JSON file as dict from fixtures/dedicated-fixture.json
                with open('fixtures/dedicated-fixture.json') as f:
                    return json.load(f)
            elif kwargs['ids'] == 'Q456':
                with open('fixtures/missing-fixture.json') as f:
                    return json.load(f)
        elif action == 'query':
            if meta == 'userinfo':
                return { 'query': { 'userinfo': { 'id': 123, 'name': 'User123' } } }
            elif meta == 'tokens':
                return { 'query': { 'tokens': { 'csrftoken': '70abcd1235215ffbc7xy34a2c7c8b12b99e62b2c+\\' } } }
        else:
            return {}

class MockSession:
    def get(action, meta=None, **kwargs):
        return MockResponse.get(action, meta, **kwargs)

def test_get_album(client, monkeypatch):
    def mockreturn():
        return MockSession

    # Set the oauth_access_token on the flask session
    with multitrack_drafting.app.test_request_context() as context:
        context.session['oauth_access_token'] = 'test token'

    # stub the authenticated_session method
    monkeypatch.setattr(multitrack_drafting, "authenticated_session", mockreturn)

    response = client.get('/album/Q123')
    html = response.get_data(as_text=True)
    assert 'Add tracks to' in html

    # Assert that the album name was correctly extracted.
    assert '<h3 class="album-name">Dedicated</h3>' in html

    # extract CSRF token
    match = re.search(r'name="csrf_token" type="hidden" value="([^"]*)"', html)
    assert match is not None

    # Assert that the user is logged in.
    assert re.search(r'Logged in as <a href=\".*\"><bdi>User123', html) is not None

def test_get_album_when_missing(client, monkeypatch):
    def mockreturn():
        return MockSession

    # Set the oauth_access_token on the flask session
    with multitrack_drafting.app.test_request_context() as context:
        context.session['oauth_access_token'] = 'test token'

    # stub the authenticated_session method
    monkeypatch.setattr(multitrack_drafting, "authenticated_session", mockreturn)

    response = client.get('/album/Q456')
    html = response.get_data(as_text=True)
    assert 'Item Q456 does not exist on Wikidata' in html
    # The form fields should be hidden.
    assert 'Tracklist' not in html
    assert 'Performer QID' not in html

# def test_post_album(client):
#     # default praise
#     response = client.get('/album/Q123')
#     html = response.get_data(as_text=True)
#     assert 'Add tracks to' in html

#     # extract CSRF token
#     match = re.search(r'name="csrf_token" type="hidden" value="([^"]*)"', html)
#     assert match is not None
#     csrf_token = match.group(1)

#     referrer = multitrack_drafting.full_url('album_get', 'Q123')
#     headers = { 'Referer': referrer }

#     # update praise
#     response = client.post('/album/Q123',
#                            data={
#                                'csrf_token': csrf_token,
#                                'praise': 'How cool!'
#                             },
#                            headers=headers)
#     html = response.get_data(as_text=True)
#     assert '<h2>How cool!</h2>' in html
#     assert 'You rock!' not in html

#     # try to update praise with wrong CSRF token
#     response = client.post('/praise',
#                            data={'csrf_token': 'wrong ' + csrf_token,
#                                  'praise': 'Boo!'},
#                            headers=headers)
#     html = response.get_data(as_text=True)
#     assert '<h2>Boo!</h2>' not in html
#     assert '<h2>How cool!</h2>' in html
#     assert 'value="Boo!"' in html  # input is repeated
