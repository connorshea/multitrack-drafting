import json
import pytest  # type: ignore
import re

import app as multitrack_drafting

@pytest.fixture
def client():
    multitrack_drafting.app.testing = True
    # Spoof the OAUTH values so the tests work even if config.yaml isn't present.
    multitrack_drafting.app.config['OAUTH'] = {'consumer_key': 'abcdefghijklmao', 'consumer_secret': 'abcdefghijklmao'}
    client = multitrack_drafting.app.test_client()

    with client:
        yield client
    # request context stays alive until the fixture is closed

# Mock the OAuth session and Wikidata API requests.
@pytest.fixture(autouse=True)
def mock_oauth(monkeypatch):
    def mockreturn():
        return MockSession

    # Set the oauth_access_token on the flask session
    with multitrack_drafting.app.test_request_context() as context:
        context.session['oauth_access_token'] = 'test token'

    # stub the authenticated_session method
    monkeypatch.setattr(multitrack_drafting, "authenticated_session", mockreturn)

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
    # Load faked responses from the Wikidata API based on what we pass in to the request.
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
    
    def post(action, **kwargs):
        if action == 'wbeditentity':
            if kwargs.get('new') == 'item':
                return { 'success': 1, 'entity': { 'id': 'Q123' } }
            elif kwargs.get('id') == 'Q123':
                return None

class MockSession:
    def get(action, meta=None, **kwargs):
        return MockResponse.get(action, meta, **kwargs)

    def post(action, **kwargs):
        return MockResponse.post(action, **kwargs)
    
def post_album_helper(
        client,
        csrf_token,
        referrer,
        tracklist,
        track_type='music_track_with_vocals',
        track_description_language='en',
        track_description='Foo',
        performer_qid='',
        recorded_at_qid='',
        producer_qid='',
        language='en',
        include_track_numbers='on'
    ):
    headers = { 'Referer': referrer }

    return client.post('/album/Q123',
                           data={
                               'csrf_token': csrf_token,
                               'track_type': track_type,
                               'track_description_language': track_description_language,
                               'track_description': track_description,
                               'tracklist': tracklist,
                               'performer_qid': performer_qid,
                               'recorded_at_qid': recorded_at_qid,
                               'producer_qid': producer_qid,
                               'language': language,
                               'include_track_numbers': include_track_numbers
                            },
                           headers=headers,
                           follow_redirects=True)

def setup_for_post_album(client):
    response = client.get('/album/Q123')
    html = response.get_data(as_text=True)
    assert 'Add tracks to' in html

    # extract CSRF token
    match = re.search(r'name="csrf_token" type="hidden" value="([^"]*)"', html)
    assert match is not None
    return match.group(1)

def test_get_album(client):
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

def test_get_album_when_missing(client):
    response = client.get('/album/Q456')
    html = response.get_data(as_text=True)
    assert 'Item Q456 does not exist on Wikidata' in html
    # The form fields should be hidden.
    assert 'Tracklist' not in html
    assert 'Performer QID' not in html

def test_basic_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    tracklist = 'Foo\nBar'
    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist=tracklist,
        track_type='music_track_with_vocals',
        track_description_language='en',
        track_description='song by Carly Rae Jepsen',
        performer_qid='123',
        recorded_at_qid='',
        producer_qid='',
        language='en',
        include_track_numbers='on'
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' in html

def test_tracklist_with_long_track_name_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    # A track name with more than 250 characters will not be accepted.
    tracklist = f'Foo\nBa{"r" * 249}'
    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist=tracklist
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' not in html
    assert 'A track name cannot be longer than 250 characters.' in html

def test_empty_tracklist_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist=''
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' not in html
    assert 'No tracklist provided.' in html

def test_tracklist_with_only_spaces_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist='     \n   '
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' not in html
    assert 'No tracklist provided.' in html

def test_tracklist_with_dupes_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist='Foo\nBar\nFoo'
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' not in html
    assert 'Tracklist cannot have duplicate track names.' in html

# Verify that we catch dupes even if they have different spacing.
def test_tracklist_with_dupes_with_spaces_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist='   Foo   \n  Bar\n \n  Foo   '
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' not in html
    assert 'Tracklist cannot have duplicate track names.' in html

def test_blank_track_description_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    tracklist='Foo\nBar'
    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist=tracklist,
        track_description='',
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' not in html
    assert 'No track description provided.' in html

def test_track_description_with_only_spaces_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    tracklist='Foo\nBar'
    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist=tracklist,
        track_description='      ',
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' not in html
    assert 'No track description provided.' in html

def test_track_description_that_is_too_long_post_album(client):
    csrf_token = setup_for_post_album(client)
    referrer = multitrack_drafting.full_url('album_get', item_id=123)

    tracklist='Foo\nBar'
    # Post the tracklist.
    response = post_album_helper(
        client=client,
        csrf_token=csrf_token,
        referrer=referrer,
        tracklist=tracklist,
        track_description='a' * 251,
    )

    html = response.get_data(as_text=True)
    assert 'Successfully created track items and tracklist.' not in html
    assert 'Track description cannot be longer than 250 characters.' in html
