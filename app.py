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
from glom import glom

app = flask.Flask(__name__)

user_agent = toolforge.set_user_agent(
    'multitrack-drafting',
    email='connor.james.shea+wikidata@gmail.com')


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
    index_php = 'https://test.wikidata.org/w/index.php'


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
    return mwapi.Session(host='https://test.wikidata.org',
                         auth=auth,
                         user_agent=user_agent)


@app.route('/')
def index() -> RRV:
    return flask.render_template('index.html')


@app.get('/album/Q<item_id>')
def album_get(item_id: int) -> RRV:
    session = authenticated_session()
    if session is None:
        # Bail out early if we aren’t logged in.
        return flask.redirect(flask.url_for('login'))

    # fetch item from Wikidata
    item_entity = session.get(action='wbgetentities', ids=f'Q{item_id}')
    # Handle the case where the item doesn't exist on Wikidata.
    item_missing = glom(item_entity, f'entities.Q{item_id}.missing', default=None)
    if item_missing != None:
        return flask.render_template('album.html',
                                     item_id=item_id,
                                     item_name='No English title on Wikidata',
                                     errors=[f'Item Q{item_id} does not exist on Wikidata'])

    item_name = glom(item_entity, f'entities.Q{item_id}.labels.en.value', default='No English title on Wikidata')

    # TODO: Add checks for whether the item is an album and whether it has a tracklist

    return flask.render_template('album.html',
                                 item_id=item_id,
                                 item_name=item_name,
                                 errors=None)


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
                                     errors=None)

    session = authenticated_session()

    if session is None:
        # Bail out early if we aren’t logged in.
        return flask.redirect(flask.url_for('login'))

    return flask.render_template('album.html',
                                 item_id=item_id,
                                 csrf_error=csrf_error,
                                 errors=None)


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
