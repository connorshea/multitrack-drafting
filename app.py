# -*- coding: utf-8 -*-

import json
import decorator
import flask
from flask.typing import ResponseReturnValue as RRV
from markupsafe import Markup
import mwapi  # type: ignore
import mwoauth  # type: ignore
import os
import random
import requests_oauthlib  # type: ignore
import stat
import string
import toolforge
from typing import Optional, Tuple
import yaml
from glom import glom, Path

app = flask.Flask(__name__)

user_agent = toolforge.set_user_agent(
    'multitrack-drafting',
    email='connor.james.shea+wikidata@gmail.com')

TEST_WIKIDATA = False

INSTANCE_OF_PROPERTY = 'P82' if TEST_WIKIDATA else 'P31'
TITLE_PROPERTY = 'P77107' if TEST_WIKIDATA else 'P1476'
PERFORMER_PROPERTY = 'P97837' if TEST_WIKIDATA else 'P175'
RECORDED_AT_PROPERTY = 'P97839' if TEST_WIKIDATA else 'P483'
PRODUCER_PROPERTY = 'P97838' if TEST_WIKIDATA else 'P162'
TRACKLIST_PROPERTY = 'P95821' if TEST_WIKIDATA else 'P658'
SERIES_ORDINAL_PROPERTY = 'P551' if TEST_WIKIDATA else 'P1545'
DURATION_PROPERTY = 'P374' if TEST_WIKIDATA else 'P2047'
ISRC_PROPERTY = 'P97842' if TEST_WIKIDATA else 'P1243'
ALBUM_ITEM = 'Q1785' if TEST_WIKIDATA else 'Q482994'
AUDIO_TRACK_ITEM = 'Q232068' if TEST_WIKIDATA else 'Q7302866'
MUSIC_TRACK_WITH_VOCALS_ITEM = 'Q232069' if TEST_WIKIDATA else 'Q55850593'
MUSIC_TRACK_WITHOUT_VOCALS_ITEM = 'Q232162' if TEST_WIKIDATA else 'Q55850643'

VALID_ALBUM_TYPES = [
    1785 if TEST_WIKIDATA else 482994, # album
    232169 if TEST_WIKIDATA else 169930, # EP
    123 if TEST_WIKIDATA else 108352648, # album release
    124 if TEST_WIKIDATA else 108352496, # single release
    125 if TEST_WIKIDATA else 108346556 # EP release
]

# The unit to use with the duration property.
SECONDS_UNIT = 'http://test.wikidata.org/entity/Q166170' if TEST_WIKIDATA else 'http://www.wikidata.org/entity/Q11574'

TRACK_TYPES = {
    'audio_track': AUDIO_TRACK_ITEM,
    'music_track_with_vocals': MUSIC_TRACK_WITH_VOCALS_ITEM,
    'music_track_without_vocals': MUSIC_TRACK_WITHOUT_VOCALS_ITEM
}

@decorator.decorator
def read_private(func, *args, **kwargs):
    try:
        f = args[0]
        fd = f.fileno()
    except AttributeError:
        pass
    except IndexError:
        pass
    else:
        mode = os.stat(fd).st_mode
        if (stat.S_IRGRP | stat.S_IROTH) & mode:
            name = getattr(f, "name", "config file")
            raise ValueError(f'{name} is readable to others, '
                             'must be exclusively user-readable!')
    return func(*args, **kwargs)


has_config = app.config.from_file('config.yaml',
                                  load=read_private(yaml.safe_load),
                                  silent=True)
if not has_config or app.testing == True:
    print('config.yaml file not found, assuming local development setup')
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(64))
    app.secret_key = random_string

if 'OAUTH' in app.config and app.testing != True:
    oauth_config = app.config['OAUTH']
    consumer_token = mwoauth.ConsumerToken(oauth_config['consumer_key'],
                                           oauth_config['consumer_secret'])
    index_php = 'https://test.wikidata.org/w/index.php' if TEST_WIKIDATA else 'https://www.wikidata.org/w/index.php'


@app.template_global()
def csrf_token() -> str:
    if 'csrf_token' not in flask.session:
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters) for _ in range(64))
        flask.session['csrf_token'] = random_string
    return flask.session['csrf_token']


@app.template_global()  # type: ignore
def form_value(name: str) -> Markup:
    if 'repeat_form' in flask.g and name in flask.request.form:
        return (Markup(r' value="') +
                Markup.escape(flask.request.form[name]) +
                Markup(r'" '))
    else:
        return Markup()


@app.template_global()  # type: ignore
def form_attributes(name: str) -> Markup:
    return (Markup(r' id="') +
            Markup.escape(name) +
            Markup(r'" name="') +
            Markup.escape(name) +
            Markup(r'" ') +
            form_value(name))  # type: ignore


@app.template_filter()
def user_link(user_name: str) -> Markup:
    user_href = 'https://www.wikidata.org/wiki/User:'
    return (Markup(r'<a href="' + user_href) +
            Markup.escape(user_name.replace(' ', '_')) +
            Markup(r'">') +
            Markup(r'<bdi>') +
            Markup.escape(user_name) +
            Markup(r'</bdi>') +
            Markup(r'</a>'))

@app.template_global()
def wikidata_link(item_id: int) -> Markup:
    url = f'https://test.wikidata.org/wiki/Q{item_id}' if TEST_WIKIDATA else f'https://www.wikidata.org/wiki/Q{item_id}'
    return Markup('<a href="' + str(url) + '" target="_blank">Q' + str(item_id) + '</a>')

@app.template_global()
def authentication_area() -> Markup:
    if 'OAUTH' not in app.config:
        return Markup()

    session = authenticated_session()
    if session is None:
        return (Markup(r'<a id="login" class="navbar-text" href="') +
                Markup.escape(flask.url_for('login')) +
                Markup(r'">Log in</a>'))

    userinfo = session.get(action='query',
                           meta='userinfo')['query']['userinfo']
    return (Markup(r'<span class="navbar-text">Logged in as ') +
            user_link(userinfo['name']) +
            Markup(r'</span>'))


def authenticated_session() -> Optional[mwapi.Session]:
    if 'oauth_access_token' not in flask.session:
        return None

    access_token = mwoauth.AccessToken(
        **flask.session['oauth_access_token'])
    auth = requests_oauthlib.OAuth1(client_key=consumer_token.key,
                                    client_secret=consumer_token.secret,
                                    resource_owner_key=access_token.key,
                                    resource_owner_secret=access_token.secret)
    return mwapi.Session(host='https://test.wikidata.org' if TEST_WIKIDATA else 'https://www.wikidata.org',
                         auth=auth,
                         user_agent=user_agent)

# TODO:
# - Figure out rate limiting and how it should be handled, to avoid the endpoint hitting errors while we're in the middle of creating the items.
#
# Create the tracklist items and return the newly-created item IDs.
def create_tracklist_items(
        session: mwapi.Session,
        tracklist: list[dict],
        performer_qid: int | None,
        recorded_at_qid: int | None,
        producer_qid: int | None,
        language: str,
        track_type: str,
        track_description_language: str,
        track_description: str,
        edit_group_id: str
    ) -> list[dict]:
    track_item_ids = []
    for track in tracklist:
        # Create track item.
        track_item = create_wikidata_track_item(
            session,
            title=track['name'],
            performer_qid=performer_qid,
            recorded_at_qid=recorded_at_qid,
            producer_qid=producer_qid,
            language=language,
            track_type=track_type,
            track_description_language=track_description_language,
            track_description=track_description,
            duration=track.get('duration'),
            isrc_id=track.get('isrc_id'),
            edit_group_id=edit_group_id
        )
        track_item_dict = { 'wikidata_id': int(track_item['entity']['id'][1:]) }
        if 'duration' in track:
            track_item_dict['duration'] = track['duration']
        if 'isrc_id' in track:
            track_item_dict['isrc_id'] = track['isrc_id']
        track_item_ids.append(track_item_dict)

    return track_item_ids

# Helper method for generating claim object dicts for the Wikidata API.
def generate_wikidata_claim_object(property_id: str, item_id: str) -> dict:
    return {
        'mainsnak': {
            'snaktype': 'value',
            'property': property_id,
            'datatype': 'wikibase-item',
            'datavalue': {
                'value': {
                    'entity-type': 'wikibase-item',
                    'numeric-id': int(item_id[1:]),
                    'id': item_id
                },
                'type': 'wikibase-entityid'
            }
        },
        'type': 'statement',
        'rank': 'normal'
    }

def generate_wikidata_monolingual_text_claim_object(property_id: str, language: str, string: str) -> dict:
    return {
        'mainsnak': {
            'snaktype': 'value',
            'property': property_id,
            'datatype': 'monolingualtext',
            'datavalue': {
                'value': {
                    'language': language,
                    'text': string
                },
                'type': 'monolingualtext'
            }
        },
        'type': 'statement',
        'rank': 'normal'
    }

def create_wikidata_track_item(
        session: mwapi.Session,
        title: str,
        performer_qid: int | None,
        recorded_at_qid: int | None,
        producer_qid: int | None,
        language: str,
        track_type: str,
        track_description_language: str,
        track_description: str,
        duration: int | None,
        isrc_id: str | None,
        edit_group_id: str
    ):
    csrf_token_from_wikidata = session.get(action='query', meta='tokens')['query']['tokens']['csrftoken']

    data = {
        'labels': [
            {
                'language': language, 'value': title
            }
        ],
        'descriptions': [
            {
                'language': track_description_language, 'value': track_description
            }
        ],
        'claims': []
    }

    # Add an 'instance of' track type.
    data['claims'].append(
        generate_wikidata_claim_object(INSTANCE_OF_PROPERTY, TRACK_TYPES[track_type])
    )

    # Add 'title' statement.
    data['claims'].append(
        generate_wikidata_monolingual_text_claim_object(TITLE_PROPERTY, language=language, string=title)
    )

    # If we have a performer, add it to the data.
    if performer_qid != None and performer_qid != '':
        data['claims'].append(
            generate_wikidata_claim_object(PERFORMER_PROPERTY, f'Q{performer_qid}')
        )

    # If we have a recording location, add it to the data.
    if recorded_at_qid != None and recorded_at_qid != '':
        data['claims'].append(
            generate_wikidata_claim_object(RECORDED_AT_PROPERTY, f'Q{recorded_at_qid}')
        )

    # If we have a producer, add it to the data.
    if producer_qid != None and producer_qid != '':
        data['claims'].append(
            generate_wikidata_claim_object(PRODUCER_PROPERTY, f'Q{producer_qid}')
        )

    # If we have the duration, add it to the data.
    if duration != None:
        data['claims'].append(
            {
                'mainsnak': {
                    'snaktype': 'value',
                    'property': DURATION_PROPERTY,
                    'datatype': 'quantity',
                    'datavalue': {
                        'value': {
                            'amount': duration,
                            'unit': SECONDS_UNIT
                        },
                        'type': 'quantity'
                    }
                },
                'type': 'statement',
                'rank': 'normal'
            }
        )
    
    # If we have an ISRC ID, add it to the data.
    if isrc_id != None and isrc_id != '':
        data['claims'].append(
            {
                'mainsnak': {
                    'snaktype': 'value',
                    'property': ISRC_PROPERTY,
                    'datatype': 'external-id',
                    'datavalue': {
                        'value': isrc_id,
                        'type': 'string'
                    }
                },
                'type': 'statement',
                'rank': 'normal'
            }
        )

    return session.post(
        action='wbeditentity',
        new='item',
        token=csrf_token_from_wikidata,
        data=json.dumps(data),
        summary=f'Create new item for music track on album. ([[:toolforge:editgroups/b/multitrack/{edit_group_id}|details]])'
    )

def add_tracklist_to_album_item(
        session: mwapi.Session,
        item_id: int,
        track_items: list[dict],
        include_track_numbers: bool,
        edit_group_id: str
    ):
    csrf_token_from_wikidata = session.get(action='query', meta='tokens')['query']['tokens']['csrftoken']

    # Add the tracklist claim.
    data = { 'claims': [] }
    for i, track_item in enumerate(track_items):
        claim = {
            'mainsnak': {
                'snaktype': 'value',
                'property': TRACKLIST_PROPERTY,
                'datatype': 'wikibase-item',
                'datavalue': {
                    'value': {
                        'entity-type': 'wikibase-item',
                        'numeric-id': track_item['wikidata_id'],
                        'id': f'Q{track_item["wikidata_id"]}'
                    },
                    'type': 'wikibase-entityid'
                }
            },
            'type': 'statement',
            'rank': 'normal',
            'qualifiers': {}
        }

        if include_track_numbers == True:
            claim['qualifiers'].update({
                SERIES_ORDINAL_PROPERTY: [
                    {
                        'snaktype': 'value',
                        'property': SERIES_ORDINAL_PROPERTY,
                        'datatype': 'string',
                        'datavalue': {
                            'value': str(i + 1),
                            'type': 'string'
                        }
                    }
                ]
            })

        if 'duration' in track_item:
            claim['qualifiers'].update({
                DURATION_PROPERTY: [
                    {
                        'snaktype': 'value',
                        'property': DURATION_PROPERTY,
                        'datatype': 'quantity',
                        'datavalue': {
                            'value': {
                                'amount': track_item['duration'],
                                'unit': SECONDS_UNIT
                            },
                            'type': 'quantity'
                        }
                    }
                ]
            })

        data['claims'].append(claim)

    return session.post(
        action='wbeditentity',
        id=f'Q{item_id}',
        token=csrf_token_from_wikidata,
        data=json.dumps(data),
        summary=f'Add tracklist entries to album. ([[:toolforge:editgroups/b/multitrack/{edit_group_id}|details]])'
    )

# We can optionally pass it an item to avoid making an extra API call.
def get_wikidata_item(session: mwapi.Session, item_id: int, item = None) -> str | None:
    if item != None:
        return item
    return glom(session.get(action='wbgetentities', ids=f'Q{item_id}'), f'entities.Q{item_id}', default=None)

def get_wikidata_instance_of(session, item_id: int, item) -> list[int] | None:
    instances_of = glom(
        get_wikidata_item(session, item_id, item),
        f'claims.{INSTANCE_OF_PROPERTY}',
        default=None
    )

    if instances_of == None:
        return instances_of

    return list(map(lambda x: glom(x, 'mainsnak.datavalue.value.numeric-id', default=None), instances_of))

def get_wikidata_item_name(session: mwapi.Session, item_id: int, lang: str = 'en', item = None) -> str | None:
    return glom(get_wikidata_item(session, item_id, item), f'labels.{lang}.value', default=None)

def check_if_item_has_property(session, item_id: int, property_id: int, item = None) -> bool:
    return glom(
        get_wikidata_item(session, item_id, item),
        f'claims.P{property_id}',
        default=None
    ) != None

def tracklist_parser(tracklist: str) -> list[dict[str, str]]:
    tracklist = tracklist.split("\n")
    result = []
    for track_parts in tracklist:
        track_parts = track_parts.split("|")
        if len(track_parts) == 3:
            result.append({"name": track_parts[0].strip(), "duration": track_parts[1].strip(), "isrc_id": track_parts[2].strip()})
        elif len(track_parts) == 2:
            result.append({"name": track_parts[0].strip(), "duration": track_parts[1].strip()})
        elif len(track_parts) == 1:
            result.append({"name": track_parts[0].strip()})

    # Remove any empty tracks.
    result = [x for x in result if x["name"] != ""]

    if len(result) == 0:
        raise ValueError('No track names in tracklist.')

    # Convert duration to seconds if duration is defined.
    for track in result:
        if "duration" in track:
            track["duration"] = duration_to_seconds(track["duration"])

    return result

def duration_to_seconds(duration):
    duration = duration.split(':')

    # Raise a ValueError if any of the duration parts are a blank string, e.g. ':15' should be invalid.
    if '' in duration:
        raise ValueError(f'Invalid duration format for \'{":".join(duration)}\'.')

    if len(duration) == 2:
        return int(duration[0]) * 60 + int(duration[1])
    elif len(duration) == 3:
        return int(duration[0]) * 3600 + int(duration[1]) * 60 + int(duration[2])
    else:
        raise ValueError(f'Invalid duration format for \'{":".join(duration)}\'.')

@app.route('/')
def index() -> RRV:
    return flask.render_template('index.html')


@app.get('/album/Q<item_id>')
def album_get(item_id: int) -> RRV:
    warnings = []
    session = authenticated_session()
    if session is None:
        # Bail out early if we aren’t logged in.
        return flask.redirect(flask.url_for('login'))

    # fetch item from Wikidata
    item_entity = get_wikidata_item(session, item_id)

    # Handle the case where the item doesn't exist on Wikidata.
    item_missing = glom(item_entity, 'missing', default=None)
    if item_missing != None:
        return flask.render_template('album.html',
                                     item_id=item_id,
                                     item_name='No English title on Wikidata',
                                     performer_item_id=None,
                                     performer_name=None,
                                     missing=True)

    item_name = glom(item_entity, 'labels.en.value', default='No English title on Wikidata')
    performer_item_id = glom(item_entity, Path('claims', PERFORMER_PROPERTY, 0, 'mainsnak', 'datavalue', 'value', 'numeric-id'), default=None)
    performer_name = None if performer_item_id == None else get_wikidata_item_name(session, performer_item_id, 'en')

    # Add a warning if it already has a tracklist
    if check_if_item_has_property(session, item_id, int(TRACKLIST_PROPERTY[1:]), item_entity) == True:
        warnings.append(f'Item Q{item_id} already has a tracklist. This may cause problems if you include track numbers, or may result in duplicate tracks.')

    # Add a warning if it isn't an album
    item_instance_of = get_wikidata_instance_of(session, item_id, item_entity)
    if item_instance_of == None:
        warnings.append(f'Item Q{item_id} has no "instance of" set and may not be an album.')
    elif len(set(item_instance_of).intersection(VALID_ALBUM_TYPES)) == 0:
        warnings.append(f'Item Q{item_id} is not an album or EP.')

    return flask.render_template('album.html',
                                 item_id=item_id,
                                 item_name=item_name,
                                 performer_item_id=performer_item_id or '',
                                 performer_name=performer_name,
                                 warnings=warnings)

# A post endpoint to redirect the user to the relevant album page.
@app.post('/album/redirect')
def album_redirect() -> RRV:
    session = authenticated_session()
    if session is None:
        # Bail out early if we aren’t logged in.
        return flask.redirect(flask.url_for('login'))

    item_id = flask.request.form.get('item_id')

    # Given 'Q123' or '123', redirect to the album page.
    if item_id.startswith('Q'):
        return flask.redirect(flask.url_for('album_get', item_id=item_id[1:]))
    else:
        return flask.redirect(flask.url_for('album_get', item_id=item_id))

@app.post('/album/Q<item_id>')
def album_post(item_id: int) -> RRV:
    csrf_error = False
    if submitted_request_valid():
        track_type = flask.request.form.get('track_type')
        track_description_language = flask.request.form.get('track_description_language')
        track_description = flask.request.form.get('track_description')
        tracklist = flask.request.form.get('tracklist')
        performer_qid = flask.request.form.get('performer_qid')
        recorded_at_qid = flask.request.form.get('recorded_at_qid')
        producer_qid = flask.request.form.get('producer_qid')
        include_track_numbers = flask.request.form.get('include_track_numbers') == 'on'
        language = flask.request.form.get('language')
    else:
        csrf_error = True
        flask.g.repeat_form = True
        # Bail out early if we hit a CSRF error.
        return flask.render_template('album.html',
                                     item_id=item_id,
                                     csrf_error=csrf_error,
                                     warnings=[])

    session = authenticated_session()

    if session is None:
        # Bail out early if we aren’t logged in.
        return flask.redirect(flask.url_for('login'))

    if track_description.isspace() or track_description == '':
        # Bail out early if we don't have a tracklist.
        flask.flash('No track description provided.', 'danger')
        return flask.redirect(flask.url_for('album_get', item_id=item_id))

    if len(track_description) > 250:
        flask.flash('Track description cannot be longer than 250 characters.', 'danger')
        return flask.redirect(flask.url_for('album_get', item_id=item_id))

    if tracklist.isspace() or tracklist == '':
        # Bail out early if we don't have a tracklist.
        flask.flash('No tracklist provided.', 'danger')
        return flask.redirect(flask.url_for('album_get', item_id=item_id))

    # Rescue ValueError exceptions from the tracklist parser.
    try:
        clean_tracklist = tracklist_parser(tracklist)
    except ValueError as e:
        flask.flash(str(e), 'danger')
        return flask.redirect(flask.url_for('album_get', item_id=item_id))

    # Validate that the tracklist doesn't have more than 50 items, and that
    # none of the tracks are longer than 250 characters (the label length
    # limit on Wikidata).
    if len(clean_tracklist) > 50:
        flask.flash('Tracklist cannot have more than 50 tracks.', 'danger')
        return flask.redirect(flask.url_for('album_get', item_id=item_id))

    track_names = [track['name'] for track in clean_tracklist]
    for track in track_names:
        if len(track) > 250:
            flask.flash('A track name cannot be longer than 250 characters.', 'danger')
            return flask.redirect(flask.url_for('album_get', item_id=item_id))

    # Validate that there are no duplicates in the tracklist.
    if len(track_names) != len(set(track_names)):
        flask.flash('Tracklist cannot have duplicate track names.', 'danger')
        return flask.redirect(flask.url_for('album_get', item_id=item_id))

    # Generate a random 10 character string for the edit group ID.
    edit_group_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))

    # Create the tracklist items.
    track_items = create_tracklist_items(
        session,
        tracklist=clean_tracklist,
        performer_qid=performer_qid,
        recorded_at_qid=recorded_at_qid,
        producer_qid=producer_qid,
        language=language,
        track_type=track_type,
        track_description_language=track_description_language,
        track_description=track_description,
        edit_group_id=edit_group_id
    )

    add_tracklist_to_album_item(session, item_id=item_id, track_items=track_items, include_track_numbers=include_track_numbers, edit_group_id=edit_group_id)

    # Provide a success message to confirm to the user that the records were created.
    flask.flash('Successfully created track items and tracklist.', 'success')

    # Redirect to the album page at the end.
    return flask.redirect(flask.url_for('album_get', item_id=item_id))


@app.route('/login')
def login() -> RRV:
    redirect, request_token = mwoauth.initiate(index_php,
                                               consumer_token,
                                               user_agent=user_agent)
    flask.session['oauth_request_token'] = dict(zip(request_token._fields,
                                                    request_token))
    return_url = flask.request.referrer
    if return_url and return_url.startswith(full_url('index')):
        flask.session['oauth_redirect_target'] = return_url
    return flask.redirect(redirect)


@app.route('/oauth/callback')
def oauth_callback() -> RRV:
    oauth_request_token = flask.session.pop('oauth_request_token', None)
    if oauth_request_token is None:
        already_logged_in = 'oauth_access_token' in flask.session
        query_string = flask.request.query_string\
                                    .decode(flask.request.url_charset)
        return flask.render_template('error-oauth-callback.html',
                                     already_logged_in=already_logged_in,
                                     query_string=query_string)
    request_token = mwoauth.RequestToken(**oauth_request_token)
    access_token = mwoauth.complete(index_php,
                                    consumer_token,
                                    request_token,
                                    flask.request.query_string,
                                    user_agent=user_agent)
    flask.session['oauth_access_token'] = dict(zip(access_token._fields,
                                                   access_token))
    flask.session.pop('csrf_token', None)
    redirect_target = flask.session.pop('oauth_redirect_target', None)
    return flask.redirect(redirect_target or flask.url_for('index'))


@app.route('/logout')
def logout() -> RRV:
    flask.session.pop('oauth_access_token', None)
    return flask.redirect(flask.url_for('index'))


def full_url(endpoint: str, **kwargs) -> str:
    scheme = flask.request.headers.get('X-Forwarded-Proto', 'http')
    return flask.url_for(endpoint, _external=True, _scheme=scheme, **kwargs)


def submitted_request_valid() -> bool:
    """Check whether a submitted POST request is valid.

    If this method returns False, the request might have been issued
    by an attacker as part of a Cross-Site Request Forgery attack;
    callers MUST NOT process the request in that case.
    """
    real_token = flask.session.get('csrf_token')
    submitted_token = flask.request.form.get('csrf_token')
    if not real_token:
        # we never expected a POST
        return False
    if not submitted_token:
        # token got lost or attacker did not supply it
        return False
    if submitted_token != real_token:
        # incorrect token (could be outdated or incorrectly forged)
        return False
    return True


# If you don’t want to handle CSRF protection in every POST handler,
# you can instead uncomment the @app.before_request decorator
# on the following function,
# which will raise a very generic error for any invalid POST.
# Otherwise, you can remove the whole function.
# @app.before_request
def require_valid_submitted_request() -> Optional[Tuple[str, int]]:
    if flask.request.method == 'POST' and not submitted_request_valid():
        return 'CSRF error', 400  # stop request handling
    return None  # continue request handling


@app.after_request
def deny_frame(response: flask.Response) -> flask.Response:
    """Disallow embedding the tool’s pages in other websites.

    Not every tool can be usefully embedded in other websites, but
    allowing embedding can expose the tool to clickjacking
    vulnerabilities, so err on the side of caution and disallow
    embedding. This can be removed (possibly only for certain pages)
    as long as other precautions against clickjacking are taken.
    """
    response.headers['X-Frame-Options'] = 'deny'
    return response
