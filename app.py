# -*- coding: utf-8 -*-

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

TEST_WIKIDATA = True
INSTANCE_OF_PROPERTY = 'P82' if TEST_WIKIDATA else 'P31'
PERFORMER_PROPERTY = 'P97837' if TEST_WIKIDATA else 'P175'
TRACKLIST_PROPERTY = 'P95821' if TEST_WIKIDATA else 'P658'
ALBUM_ITEM = 'Q1785' if TEST_WIKIDATA else 'Q482994'

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
if not has_config:
    print('config.yaml file not found, assuming local development setup')
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(64))
    app.secret_key = random_string

if 'OAUTH' in app.config:
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

# TODO: Add a function to create the tracklist items.
def create_tracklist_items(tracklist: str, performer_qid: int | None, include_track_numbers: bool) -> None:
    print(tracklist)
    return None

# We can optionally pass it an item to avoid making an extra API call.
def get_wikidata_item(session, item_id: int, item = None) -> str | None:
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

def get_wikidata_item_name(session, item_id: int, lang: str = 'en') -> str | None:
    return glom(get_wikidata_item(session, item_id), f'labels.{lang}.value', default=None)

def check_if_item_has_property(session, item_id: int, property_id: int, item = None) -> bool:
    return glom(
        get_wikidata_item(session, item_id, item),
        f'claims.P{property_id}',
        default=None
    ) != None

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
                                     errors=[f'Item Q{item_id} does not exist on Wikidata'])

    item_name = glom(item_entity, 'labels.en.value', default='No English title on Wikidata')
    performer_item_id = glom(item_entity, Path('claims', PERFORMER_PROPERTY, 0, 'mainsnak', 'datavalue', 'value', 'numeric-id'), default=None)
    performer_name = None if performer_item_id == None else get_wikidata_item_name(session, performer_item_id, 'en')

    # Add a warning if it already has a tracklist
    if check_if_item_has_property(session, item_id, TRACKLIST_PROPERTY[1:], item_entity) == True:
        warnings.append(f'Item Q{item_id} already has a tracklist.')

    # Add a warning if it isn't an album
    item_instance_of = get_wikidata_instance_of(session, item_id, item_entity)
    if item_instance_of == None:
        warnings.append(f'Item Q{item_id} has no "instance of" set.')
    elif int(ALBUM_ITEM[1:]) not in item_instance_of:
        warnings.append(f'Item Q{item_id} is not an album.')

    return flask.render_template('album.html',
                                 item_id=item_id,
                                 item_name=item_name,
                                 performer_item_id=performer_item_id,
                                 performer_name=performer_name,
                                 errors=None,
                                 warnings=warnings)


@app.post('/album/Q<item_id>')
def album_post(item_id: int) -> RRV:
    csrf_error = False
    if submitted_request_valid():
        tracklist = flask.request.form.get('tracklist')
        performer_qid = flask.request.form.get('performer_qid')
        include_track_numbers = flask.request.form.get('include_track_numbers') == 'on'

        print(item_id)
        print(tracklist)
        print(performer_qid)
        print(include_track_numbers)
    else:
        csrf_error = True
        flask.g.repeat_form = True
        # Bail out early if we hit a CSRF error.
        return flask.render_template('album.html',
                                     item_id=item_id,
                                     csrf_error=csrf_error,
                                     errors=None,
                                     warnings=[])

    session = authenticated_session()

    if session is None:
        # Bail out early if we aren’t logged in.
        return flask.redirect(flask.url_for('login'))

    create_tracklist_items(tracklist, performer_qid, include_track_numbers)

    # TODO: Figure out the best way to render this without losing the item_name we pulled from Wikidata, and any other checks.
    return flask.render_template('album.html',
                                 item_id=item_id,
                                 csrf_error=csrf_error,
                                 errors=None,
                                 warnings=[])


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
