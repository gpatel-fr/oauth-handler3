#!/usr/bin/env python

import base64
import datetime
import hashlib
import logging
import os
import random
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse

import jinja2
import json

from flask import Flask, request, redirect, Response

from google.appengine.api import memcache
from google.appengine.api import urlfetch
from google.appengine.api import wrap_wsgi_app

import dbmodel
import password_generator
import settings
import simplecrypt


my_key = os.environ.get("GAE_VERSION", "Missing")

app = Flask(__name__)
app.wsgi_app = wrap_wsgi_app(app.wsgi_app, use_deferred=True)

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    autoescape=True,
)

if settings.TESTING:
    logging.basicConfig(level=logging.DEBUG)


def set_status(response, code, msg):
    response.status_code = code
    if msg and len(msg) > 0:
        response.status = msg


def wrap_json(request, obj, code=200, status_msg=""):
    """This method helps send JSON to the client"""
    data = json.dumps(obj)
    cb = request.args.get("callback")
    if cb is None:
        cb = request.args.get("jsonp")

    if cb is not None and cb != "":
        data = cb + "(" + data + ")"
        response = Response(data)
        set_status(response, code, status_msg)
        response.headers["Content-Type"] = "application/javascript"
    else:
        response = Response(data)
        set_status(response, code, status_msg)
        response.headers["Content-Type"] = "application/json"

    return response


def find_provider_and_service(provider_id):
    providers = [n for n in settings.SERVICES if n["id"] == provider_id]
    if len(providers) != 1:
        raise Exception("No such provider: " + provider_id)

    provider = providers[0]
    return provider, settings.LOOKUP[provider["type"]]


def find_service(service_id):
    service_id = service_id.lower()
    if service_id in settings.LOOKUP:
        return settings.LOOKUP[service_id]

    provider, service = find_provider_and_service(service_id)
    return service


def create_authtoken(provider_id, token):
    # We store the ID if we get it back
    if "user_id" in token:
        user_id = token["user_id"]
    else:
        user_id = "N/A"

    exp_secs = 1800  # 30 min guess
    try:
        exp_secs = int(token["expires_in"])
    except:
        pass

    # Create a random password and encrypt the response
    # This ensures that a hostile takeover will not get access
    # to stored access and refresh tokens
    password = password_generator.generate_pass()
    cipher = simplecrypt.encrypt(password, json.dumps(token))

    # Convert to text and prepare for storage
    b64_cipher = base64.b64encode(cipher)
    expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=exp_secs)

    entry = None
    keyid = None

    # Find a random un-used user ID, and store the encrypted data
    while entry is None:
        keyid = "%030x" % random.randrange(16**32)
        entry = dbmodel.insert_new_authtoken(
            keyid, user_id, b64_cipher, expires, provider_id
        )
        if settings.TESTING and (entry is not None):
            logging.info(
                f"successfully inserted new auth token: random keyid {keyid} user {user_id} encrypted password {b64_cipher} expires {expires} provider {provider_id}"
            )

    # Return the keyid and authid
    return keyid, keyid + ":" + password


@app.route("/login")
def login():
    """Creates a state and redirects the user to the login page"""
    try:
        provider, service = find_provider_and_service(request.args.get("id", None))

        # Find a random un-used state token
        stateentry = None
        while stateentry is None:
            statetoken = "%030x" % random.randrange(16**32)
            stateentry = dbmodel.insert_new_statetoken(
                statetoken,
                provider["id"],
                request.args.get("token", None),
                request.args.get("tokenversion", None),
            )

        link = service["login-url"]
        link += "?client_id=" + service["client-id"]
        link += "&response_type=code"
        link += "&scope=" + provider["scope"]
        link += "&state=" + statetoken
        if "extraurl" in provider:
            link += "&" + provider["extraurl"]
        link += "&redirect_uri=" + service["redirect-uri"]

        if settings.TESTING:
            logging.info(f"redirected to {link}")

        return redirect(link)

    except:
        logging.exception(f"login handler error")
        r = wrap_json(request, {"error": "Server error"}, 500, "Server error")
        return r


@app.route("/")
def root():
    """Renders the index.html file with contents from settings.py"""
    # If the request contains a token,
    #  register this with a limited lifetime
    #  so the caller can grab the authid automatically
    if request.args.get("token", None) is not None:
        dbmodel.create_fetch_token(request.args.get("token"))
        if settings.TESTING:
            logging.info(f"Created redir with token {request.args.get('token')}")

    filtertype = request.args.get("type", None)

    tokenversion = settings.DEFAULT_TOKEN_VERSION

    try:
        if request.args.get("tokenversion") is not None:
            tokenversion = int(request.args.get("tokenversion"))
    except:
        pass

    templateitems = []
    for n in settings.SERVICES:
        service = settings.LOOKUP[n["type"]]

        # If there is a ?type= parameter, filter the results
        if filtertype is not None and filtertype != n["id"]:
            continue

        # If the client id is invalid or missing, skip the entry
        if service["client-id"] is None or service["client-id"][0:8] == "XXXXXXXX":
            continue

        if filtertype is None and "hidden" in n and n["hidden"]:
            continue

        link = ""
        if "cli-token" in service and service["cli-token"]:
            link = "/cli-token?id=" + n["id"]
            if request.args.get("token", None) is not None:
                link += "&token=" + request.args.get("token")
        else:
            link = "/login?id=" + n["id"]
            if request.args.get("token", None) is not None:
                link += "&token=" + request.args.get("token")

            if tokenversion is not None:
                link += "&tokenversion=" + str(tokenversion)

        notes = ""
        if "notes" in n:
            notes = n["notes"]

        brandimg = ""
        if "brandimage" in n:
            brandimg = n["brandimage"]

        templateitems.append(
            {
                "display": n["display"],
                "authlink": link,
                "id": n["id"],
                "notes": notes,
                "servicelink": n["servicelink"],
                "brandimage": brandimg,
            }
        )

    template = JINJA_ENVIRONMENT.get_template("index.html")
    return template.render(
        {
            "redir": request.args.get("redirect", None),
            "appname": settings.APP_NAME,
            "longappname": settings.SERVICE_DISPLAYNAME,
            "providers": templateitems,
            "tokenversion": tokenversion,
        }
    )


@app.route("/logged-in")
def logged_in():
    """
    Handles the login callback from the OAuth server
    This is called after the user grants access on the remote server
    After grabbing the refresh token, the logged-in.html page is
    rendered
    """

    display = "Unknown"
    try:
        # Grab state and code from request
        state = request.args.get("state")
        code = request.args.get("code")

        if settings.TESTING:
            logging.info(f"Log-in with code {code}, and state {state}")

        if state is None or code is None:
            raise Exception("Response is missing state or code")

        statetoken = dbmodel.StateToken.get_by_id(state)
        if statetoken is None:
            raise Exception("No such state found")

        if statetoken.expires < datetime.datetime.utcnow():
            raise Exception("State token has expired")

        provider, service = find_provider_and_service(statetoken.service)

        display = provider["display"]

        redir_uri = service["redirect-uri"]
        if request.args.get("token") is not None:
            redir_uri += request.args.get("token")

        if settings.TESTING:
            logging.info(f"Got log-in with url {redir_uri}")
            logging.info(f"Sending to {service['auth-url']}")

        # Some services are slow...
        urlfetch.set_default_fetch_deadline(20)

        # With the returned code, request a refresh and access token
        url = service["auth-url"]

        request_params = {
            "client_id": service["client-id"],
            "redirect_uri": redir_uri,
            "client_secret": service["client-secret"],
            "state": state,
            "code": code,
            "grant_type": "authorization_code",
        }

        # Some services do not allow the state to be passed
        if (
            "no-state-for-token-request" in service
            and service["no-state-for-token-request"]
        ):
            del request_params["state"]

        data = urllib.parse.urlencode(request_params)
        if settings.TESTING:
            logging.info(f"REQ RAW sent to {url} : {data}")

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            req = urllib.request.Request(url, data.encode("utf-8"), headers)
            f = urllib.request.urlopen(req)
            content = f.read()
            f.close()
        except urllib.error.HTTPError as err:
            logging.info(f"ERR-CODE: {err.code}")
            logging.info(f"ERR-BODY: {err.read()}")
            raise err

        if settings.TESTING:
            logging.info(f"RESP RAW: {content}")

        # OAuth response is JSON
        resp = json.loads(content)

        # If this is a service that does not use refresh tokens,
        # we just return the access token to the caller
        if "no-refresh-tokens" in service and service["no-refresh-tokens"]:
            dbmodel.update_fetch_token(statetoken.fetchtoken, resp["access_token"])

            # Report results to the user
            template_values = {
                "service": display,
                "appname": settings.APP_NAME,
                "longappname": settings.SERVICE_DISPLAYNAME,
                "authid": resp["access_token"],
                "fetchtoken": statetoken.fetchtoken,
            }

            template = JINJA_ENVIRONMENT.get_template("logged-in.html")
            return template.render(template_values)
            statetoken.key.delete()

            logging.info(f"Returned access token for service {provider['id']}")
            return

        # This happens in some cases with Google's OAuth
        if "refresh_token" not in resp:
            if "deauthlink" in provider:
                template_values = {
                    "service": display,
                    "authid": "Server error, you must de-authorize "
                    + settings.APP_NAME,
                    "showdeauthlink": "true",
                    "deauthlink": provider["deauthlink"],
                    "fetchtoken": "",
                }

                template = JINJA_ENVIRONMENT.get_template("logged-in.html")
                statetoken.key.delete()
                return template.render(template_values)

            else:
                raise Exception(
                    "No refresh token found, try to de-authorize the application with the provider"
                )

        # v2 tokens are just the provider name and the refresh token
        # and they have no stored state on the server
        if statetoken.version == 2:
            authid = "v2:" + statetoken.service + ":" + resp["refresh_token"]
            dbmodel.update_fetch_token(statetoken.fetchtoken, authid)

            # Report results to the user
            template_values = {
                "service": display,
                "appname": settings.APP_NAME,
                "longappname": settings.SERVICE_DISPLAYNAME,
                "authid": authid,
                "fetchtoken": statetoken.fetchtoken,
            }

            template = JINJA_ENVIRONMENT.get_template("logged-in.html")
            statetoken.key.delete()

            logging.info(f"Returned refresh token for service {provider['id']}")

            return template.render(template_values)

        # Return the id and password to the user
        keyid, authid = create_authtoken(provider["id"], resp)

        fetchtoken = statetoken.fetchtoken

        # If this was part of a polling request, signal completion
        dbmodel.update_fetch_token(fetchtoken, authid)

        # Report results to the user
        template_values = {
            "service": display,
            "appname": settings.APP_NAME,
            "longappname": settings.SERVICE_DISPLAYNAME,
            "authid": authid,
            "fetchtoken": fetchtoken,
        }

        template = JINJA_ENVIRONMENT.get_template("logged-in.html")
        statetoken.key.delete()
        logging.info(f"Created new authid {keyid} for service {provider['id']}")
        return template.render(template_values)

    except:
        logging.exception(f"handler error for {display}")

        template_values = {
            "service": display,
            "appname": settings.APP_NAME,
            "longappname": settings.SERVICE_DISPLAYNAME,
            "authid": "Server error, close window and try again",
            "fetchtoken": "",
        }

        template = JINJA_ENVIRONMENT.get_template("logged-in.html")
        return template.render(template_values)


@app.route("/cli-token")
def cli_token():
    """Renders the cli-token.html page"""
    provider, service = find_provider_and_service(request.args.get("id", None))

    template_values = {
        "service": provider["display"],
        "appname": settings.APP_NAME,
        "longappname": settings.SERVICE_DISPLAYNAME,
        "id": provider["id"],
        "fetchtoken": request.args.get("token", ""),
    }

    template = JINJA_ENVIRONMENT.get_template("cli-token.html")
    return template.render(template_values)


@app.route("/cli-token-login", methods=["POST"])
def cli_token_login():
    """Handler that processes cli-token login and redirects the user to the logged-in page"""

    display = "Unknown"
    error = "Server error, close window and try again"
    try:
        provider_id = request.form["id"]
        fetch_token = request.form["fetchtoken"]
        provider, service = find_provider_and_service(provider_id)
        display = provider["display"]

        try:
            data = request.form["token"]
            content = base64.urlsafe_b64decode(str(data) + "=" * (-len(data) % 4))
            resp = json.loads(content)
        except:
            error = "Error: Invalid CLI token"
            raise

        urlfetch.set_default_fetch_deadline(20)
        url = service["auth-url"]
        data = urllib.parse.urlencode(
            {
                "client_id": service["client-id"],
                "grant_type": "password",
                "scope": provider["scope"],
                "username": resp["username"],
                "password": resp["auth_token"],
            }
        )
        try:
            req = urllib.request.Request(
                url,
                data.encode("utf-8"),
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
            f = urllib.request.urlopen(req)
            content = f.read()
            f.close()
        except urllib.error.HTTPError as err:
            if err.code == 401:
                # If trying to re-use a single-use cli token
                error = "Error: CLI token could not be authorized, create a new and try again"
            raise err

        resp = json.loads(content)

        keyid, authid = create_authtoken(provider_id, resp)

        # If this was part of a polling request, signal completion
        dbmodel.update_fetch_token(fetch_token, authid)

        # Report results to the user
        template_values = {
            "service": display,
            "appname": settings.APP_NAME,
            "longappname": settings.SERVICE_DISPLAYNAME,
            "authid": authid,
            "fetchtoken": fetch_token,
        }

        logging.info(f"Created new authid {keyid} for service {provider_id}")

        template = JINJA_ENVIRONMENT.get_template("logged-in.html")
        return template.render(template_values)

    except:
        logging.exception(f"handler error for {display}")

        template_values = {
            "service": display,
            "appname": settings.APP_NAME,
            "longappname": settings.SERVICE_DISPLAYNAME,
            "authid": error,
            "fetchtoken": "",
        }

        template = JINJA_ENVIRONMENT.get_template("logged-in.html")
        return template.render(template_values)


@app.route("/fetch")
def fetch():
    """Handler that returns the authid associated with a token"""
    try:
        fetchtoken = request.args.get("token")

        if fetchtoken is None or fetchtoken == "":
            return wrap_json(request, {"error": "Missing token"})

        entry = dbmodel.FetchToken.get_by_id(fetchtoken)
        if entry is None:
            return wrap_json(request, {"error": "No such entry"})

        if entry.expires < datetime.datetime.utcnow():
            return wrap_json(request, {"error": "Entry expired"})

        if entry.authid is None or entry.authid == "":
            return wrap_json(request, {"wait": "Not ready"})

        entry.fetched = True
        entry.put()

        return wrap_json(request, {"authid": entry.authid})
    except:
        logging.exception(f"handler error")
        return wrap_json(request, {"error": "Server error"}, 500, "Server error")


@app.route("/token-state")
def token_state():
    """Handler to query the state of an active token"""
    try:
        fetchtoken = request.args.get("token")

        if fetchtoken is None or fetchtoken == "":
            return wrap_json(request, {"error": "Missing fetch token"})

        entry = dbmodel.FetchToken.get_by_id(fetchtoken)
        if entry is None:
            return wrap_json(request, {"error": "No such entry"})

        if entry.expires < datetime.datetime.utcnow():
            return wrap_json(request, {"error": "entry expired"})

        if entry.authid is None or entry.authid == "":
            return wrap_json(request, {"wait": "Not ready"})

        return wrap_json(request, {"success": entry.fetched})
    except:
        logging.exception(f"handler error")
        return wrap_json(request, {"error": "Server error"}, 500, "Server error")


"""
Handler that retrieves a new access token,
from the provided refresh token
"""


def handle_v2(inputfragment):
    servicetype = "Unknown"
    try:
        if inputfragment.find(":") <= 0:
            response.headers["X-Reason"] = "Invalid authid in query"
            set_status(response, 400, "Invalid authid in query")
            return

        servicetype = inputfragment[: inputfragment.index(":")]
        refresh_token = inputfragment[inputfragment.index(":") + 1 :]

        service = find_service(servicetype)
        if service is None:
            raise Exception("No such service")

        if refresh_token is None or len(refresh_token.strip()) == 0:
            raise Exception("No token provided")

        tokenhash = hashlib.md5(refresh_token.encode("utf-8")).hexdigest()

        if settings.RATE_LIMIT > 0:
            ratelimiturl = "/ratelimit?id=" + tokenhash + "&adr=" + request.remote_addr
            ratelimit = memcache.get(ratelimiturl)

            if ratelimit is None:
                memcache.add(key=ratelimiturl, value=1, time=60 * 60)
            elif ratelimit > settings.RATE_LIMIT:
                logging.info(f"Rate limit response to: {tokenhash}")
                response.headers[
                    "X-Reason"
                ] = "Too many request for this key, wait 60 minutes"
                set_status(
                    response, 503, "Too many request for this key, wait 60 minutes"
                )
                return
            else:
                memcache.incr(ratelimiturl)

        cacheurl = "/v2/refresh?id=" + tokenhash

        cached_res = memcache.get(cacheurl)
        if cached_res is not None and type(cached_res) != type(""):
            exp_secs = (int)(
                (cached_res["expires"] - datetime.datetime.utcnow()).total_seconds()
            )

            if exp_secs > 30:
                logging.info(
                    f"Serving cached response to: {tokenhash}, expires in {exp_secs} secs"
                )
                return json.dumps(
                    {
                        "access_token": cached_res["access_token"],
                        "expires": exp_secs,
                        "type": cached_res["type"],
                    }
                )
            else:
                logging.info(
                    f"Cached response to: {tokenhash} is invalid because it expires in {exp_secs} secs"
                )

        url = service["auth-url"]
        request_params = {
            "client_id": service["client-id"],
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if "client-secret" in service:
            request_params["client_secret"] = service["client-secret"]
        if "redirect-uri" in service:
            request_params["redirect_uri"] = service["redirect-uri"]

        data = urllib.parse.urlencode(request_params)

        urlfetch.set_default_fetch_deadline(20)

        req = urllib.request.Request(
            url,
            data.encode("utf-8"),
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        f = urllib.request.urlopen(req)
        content = f.read()
        f.close()

        resp = json.loads(content)
        exp_secs = int(resp["expires_in"])
        expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=exp_secs)

        cached_res = {
            "access_token": resp["access_token"],
            "expires": expires,
            "type": servicetype,
        }

        memcache.set(key=cacheurl, value=cached_res, time=exp_secs - 10)
        logging.info(
            f"Caching response to: {tokenhash} for {exp_secs - 10} secs, service: {servicetype}"
        )

        # Write the result back to the client
        return json.dumps(
            {
                "access_token": resp["access_token"],
                "expires": exp_secs,
                "type": servicetype,
            }
        )

    except:
        logging.exception(f"handler error for {servicetype}")
        response.headers["X-Reason"] = "Server error"
        set_status(response, 500, "Server error")
        return response


"""
Handler that retrieves a new access token,
by decrypting the stored blob to retrieve the
refresh token, and then requesting a new access
token
"""


def process(authid):
    servicetype = "Unknown"
    response = Response()
    try:
        if authid is None or authid == "":
            logging.info(f"No authid in query")
            response.headers["X-Reason"] = "No authid in query"
            set_status(response, 400, "No authid in query")
            return response

        if authid.find(":") <= 0:
            logging.info(f"Invalid authid in query")
            response.headers["X-Reason"] = "Invalid authid in query"
            set_status(response, 400, "Invalid authid in query")
            return response

        keyid = authid[: authid.index(":")]
        password = authid[authid.index(":") + 1 :]

        if settings.WORKER_OFFLOAD_RATIO > random.random():
            workers = memcache.get("worker-urls")
            # logging.info('workers: %s', workers)
            if workers is not None and len(workers) > 0:
                newloc = random.choice(workers)
                logging.info(f"Redirecting request for id {keyid} to {newloc}")
                response.headers["Location"] = newloc
                set_status(response, 302, "Found")
                return response

        if keyid == "v2":
            return handle_v2(password)

        if settings.RATE_LIMIT > 0:
            ratelimiturl = "/ratelimit?id=" + keyid + "&adr=" + request.remote_addr
            ratelimit = memcache.get(ratelimiturl)

            if ratelimit is None:
                memcache.add(key=ratelimiturl, value=1, time=60 * 60)
            elif ratelimit > settings.RATE_LIMIT:
                logging.info(f"Rate limit response to: {keyid}")
                response.headers[
                    "X-Reason"
                ] = "Too many request for this key, wait 60 minutes"
                set_status(
                    response, 503, "Too many request for this key, wait 60 minutes"
                )
                return
            else:
                memcache.incr(ratelimiturl)

        cacheurl = (
            "/refresh?id="
            + keyid
            + "&h="
            + hashlib.sha256(password.encode("utf-8")).hexdigest()
        )

        cached_res = memcache.get(cacheurl)
        if cached_res is not None and type(cached_res) != type(""):
            exp_secs = (int)(
                (cached_res["expires"] - datetime.datetime.utcnow()).total_seconds()
            )

            if exp_secs > 30:
                logging.info(
                    f"Serving cached response to: {keyid}, expires in {exp_secs} secs"
                )
                return json.dumps(
                    {
                        "access_token": cached_res["access_token"],
                        "expires": exp_secs,
                        "type": cached_res["type"],
                    }
                )
            else:
                logging.info(
                    f"Cached response to: {keyid} is invalid because it expires in {exp_secs} secs"
                )

        # Find the entry
        entry = dbmodel.AuthToken.get_by_id(keyid)
        if entry is None:
            logging.info(f"can't find keyid {keyid}")
            response.headers["X-Reason"] = "No such key"
            set_status(response, 404, "No such key")
            return response

        servicetype = entry.service

        # Decode
        data = base64.b64decode(entry.blob)
        resp = None

        # Decrypt
        try:
            resp = json.loads(simplecrypt.decrypt(password, data).decode("utf8"))
        except:
            logging.exception(f"decrypt error")
            response.headers["X-Reason"] = "Invalid authid password"
            set_status(response, 400, "Invalid authid password")
            return response

        service = find_service(entry.service)

        # Issue a refresh request
        url = service["auth-url"]
        request_params = {
            "client_id": service["client-id"],
            "grant_type": "refresh_token",
            "refresh_token": resp["refresh_token"],
        }
        if "client-secret" in service:
            request_params["client_secret"] = service["client-secret"]
        if "redirect-uri" in service:
            request_params["redirect_uri"] = service["redirect-uri"]

        # Some services do not allow the state to be passed
        if (
            "no-redirect_uri-for-refresh-request" in service
            and service["no-redirect_uri-for-refresh-request"]
        ):
            del request_params["redirect_uri"]

        data = urllib.parse.urlencode(request_params)
        if settings.TESTING:
            logging.info(f"REQ RAW sent to {url}: {data}")
        urlfetch.set_default_fetch_deadline(20)

        try:
            req = urllib.request.Request(
                url,
                data.encode("utf-8"),
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
            f = urllib.request.urlopen(req)
            content = f.read()
            f.close()
        except urllib.error.HTTPError as err:
            logging.info(f"ERR-CODE: {err.code}")
            logging.info(f"ERR-BODY: {err.read()}")
            raise err

        # Store the old refresh_token as some servers do not send it again
        rt = resp["refresh_token"]

        # Read the server response
        resp = json.loads(content)
        exp_secs = int(resp["expires_in"])

        # Set the refresh_token if it was missing
        if "refresh_token" not in resp:
            resp["refresh_token"] = rt

        # Encrypt the updated response
        cipher = simplecrypt.encrypt(password, json.dumps(resp))
        entry.expires = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=exp_secs
        )
        entry.blob = base64.b64encode(cipher)
        entry.put()

        cached_res = {
            "access_token": resp["access_token"],
            "expires": entry.expires,
            "type": servicetype,
        }

        memcache.set(key=cacheurl, value=cached_res, time=exp_secs - 10)
        logging.info(
            f"Caching response to: {keyid} for {exp_secs - 10} secs, service: {servicetype}"
        )

        # Write the result back to the client
        return json.dumps(
            {
                "access_token": resp["access_token"],
                "expires": exp_secs,
                "type": servicetype,
                "v2_authid": "v2:" + entry.service + ":" + rt,
            }
        )

    except:
        logging.exception(f"handler error for {servicetype}")
        response.headers["X-Reason"] = "Server error"
        set_status(response, 500, "Server error")
        return response


@app.route("/refresh")
def refresh():
    authid = request.args.get("authid")

    if authid is None or authid == "":
        authid = request.headers["X-AuthID"]

    return process(authid)


@app.route("/refresh", methods=["POST"])
def refresh_post():
    authid = request.args.get("authid")

    if authid is None or authid == "":
        authid = request.headers["X-AuthID"]

    return process(authid)


@app.route("/revoke")
def revoke():
    """Renders the revoke.html page"""

    template_values = {"appname": settings.SERVICE_DISPLAYNAME}

    template = JINJA_ENVIRONMENT.get_template("revoke.html")
    return template.render(template_values)


@app.route("/revoked", methods=["POST"])
def revoked():
    """Revokes an issued auth token, and renders the revoked.html page"""

    def do_revoke():
        try:
            authid = request.args.get("authid")
            if authid is None or authid == "":
                return "Error: No authid in query"

            if authid.find(":") <= 0:
                return "Error: Invalid authid in query"

            keyid = authid[: authid.index(":")]
            password = authid[authid.index(":") + 1 :]

            if keyid == "v2":
                return "Error: The token must be revoked from the service provider. You can de-authorize the application on the storage providers website."

            entry = dbmodel.AuthToken.get_by_id(keyid)
            if entry is None:
                return "Error: No such user"

            data = base64.b64decode(entry.blob)
            resp = None

            try:
                resp = json.loads(simplecrypt.decrypt(password, data).decode("utf8"))
            except:
                logging.exception(f"decrypt error")
                return "Error: Invalid authid password"

            entry.key.delete()
            return "Token revoked"

        except:
            logging.exception(f"handler error")
            return "Error: Server error"

    result = do_revoke()

    template_values = {"result": result, "appname": settings.SERVICE_DISPLAYNAME}

    template = JINJA_ENVIRONMENT.get_template("revoked.html")
    return template.render(template_values)


@app.route("/cleanup")
def cleanup():
    """Cron activated page that expires old items from the database"""

    # Delete all expired fetch tokens
    for n in dbmodel.FetchToken.gql("WHERE expires < :1", datetime.datetime.utcnow()):
        n.key.delete()

    # Delete all expired state tokens
    for n in dbmodel.StateToken.gql("WHERE expires < :1", datetime.datetime.utcnow()):
        n.key.delete()

    # Delete all tokens not having seen use in a year
    for n in dbmodel.AuthToken.gql(
        "WHERE expires < :1",
        (datetime.datetime.utcnow() + datetime.timedelta(days=-365)),
    ):
        n.key.delete()


@app.route("/export")
def export():
    """
    Handler that exports the refresh token,
    for use by the backend handlers
    """
    try:
        response = Response()
        if (
            len(settings.API_KEY) < 10
            or request.headers["X-APIKey"] != settings.API_KEY
        ):
            if len(settings.API_KEY) < 10:
                logging.info(f"No api key loaded")

            response.headers["X-Reason"] = "Invalid API key"
            set_status(response, 403, "Invalid API key")
            return response

        authid = request.headers["X-AuthID"]

        if authid is None or authid == "":
            response.headers["X-Reason"] = "No authid in query"
            set_status(response, 400, "No authid in query")
            return response

        if authid.find(":") <= 0:
            response.headers["X-Reason"] = "Invalid authid in query"
            set_status(response, 400, "Invalid authid in query")
            return response

        keyid = authid[: authid.index(":")]
        password = authid[authid.index(":") + 1 :]

        if keyid == "v2":
            response.headers["X-Reason"] = "No v2 export possible"
            set_status(response, 400, "No v2 export possible")
            return response

        # Find the entry
        entry = dbmodel.AuthToken.get_by_id(keyid)
        if entry is None:
            response.headers["X-Reason"] = "No such key"
            set_status(response, 404, "No such key")
            return response

        # Decode
        data = base64.b64decode(entry.blob)
        resp = None

        # Decrypt
        try:
            resp = json.loads(simplecrypt.decrypt(password, data).decode("utf8"))
        except:
            logging.exception(f"decrypt error")
            response.headers["X-Reason"] = "Invalid authid password"
            set_status(response, 400, "Invalid authid password")
            return response

        resp["service"] = entry.service

        logging.info(f"Exported {len(json.dumps(resp))} bytes for keyid {keyid}")

        # Write the result back to the client
        return wrap_json(request, json.dumps(resp))
    except:
        logging.exception(f"handler error")
        response.headers["X-Reason"] = "Server error"
        set_status(response, 500, "Server error")
        return response


@app.route("/import", methods=["POST"])
def do_import():
    """
    Handler that imports the refresh token,
    for use by the backend handlers
    """

    try:
        response = Response()
        if (
            len(settings.API_KEY) < 10
            or request.headers["X-APIKey"] != settings.API_KEY
        ):
            response.headers["X-Reason"] = "Invalid API key"
            set_status(response, 403, "Invalid API key")
            return response

        authid = request.headers["X-AuthID"]

        if authid is None or authid == "":
            response.headers["X-Reason"] = "No authid in query"
            set_status(response, 400, "No authid in query")
            return response

        if authid.find(":") <= 0:
            response.headers["X-Reason"] = "Invalid authid in query"
            set_status(response, 400, "Invalid authid in query")
            return response

        keyid = authid[: authid.index(":")]
        password = authid[authid.index(":") + 1 :]

        if keyid == "v2":
            response.headers["X-Reason"] = "No v2 import possible"
            set_status(response, 400, "No v2 import possible")
            return response

        # Find the entry
        entry = dbmodel.AuthToken.get_by_id(keyid)
        if entry is None:
            response.headers["X-Reason"] = "No such key"
            set_status(response, 404, "No such key")
            return response

        # Decode
        data = base64.b64decode(entry.blob)
        resp = None

        # Decrypt
        try:
            resp = json.loads(simplecrypt.decrypt(password, data).decode("utf8"))
        except:
            logging.exception(f"decrypt error")
            response.headers["X-Reason"] = "Invalid authid password"
            set_status(response, 400, "Invalid authid password")
            return response

        resp = json.loads(request.body)
        if not "refresh_token" in resp:
            logging.info(f"Import blob does not contain a refresh token")
            response.headers[
                "X-Reason"
            ] = "Import blob does not contain a refresh token"
            set_status(response, 400, "Import blob does not contain a refresh token")
            return response

        if not "expires_in" in resp:
            logging.info(f"Import blob does not contain expires_in")
            response.headers["X-Reason"] = "Import blob does not contain expires_in"
            set_status(response, 400, "Import blob does not contain expires_in")
            return response

        logging.info(f"Imported {len(json.dumps(resp))} for keyid {keyid}")

        resp["service"] = entry.service
        exp_secs = int(resp["expires_in"]) - 10

        cipher = simplecrypt.encrypt(password, json.dumps(resp))
        entry.expires = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=exp_secs
        )
        entry.blob = base64.b64encode(cipher)
        entry.put()

        # Write the result back to the client
        response.headers["Content-Type"] = "application/json"
        return json.dumps(resp)
    except:
        logging.exception(f"handler error")
        response.headers["X-Reason"] = "Server error"
        set_status(response, 500, "Server error")
        return response


@app.route("/checkalive")
def check_alive():
    """
    Handler that exports the refresh token,
    for use by the backend handlers
    """
    if settings.WORKER_URLS is None:
        return

    data = "%030x" % random.randrange(16**32)

    validhosts = []

    for n in settings.WORKER_URLS:
        try:
            url = n[: -len("refresh")] + "isalive?data=" + data
            logging.info(f"Checking if server is alive: {url}")

            req = urllib.request.Request(url)
            f = urllib.request.urlopen(req)
            content = f.read()
            f.close()

            resp = json.loads(content)
            if resp["data"] != data:
                logging.info(
                    f"Bad response, was {resp['data']}, should have been {data}"
                )
            else:
                validhosts.append(n)
        except:
            logging.exception(f"handler error")

    logging.info(f"Valid hosts are: {validhosts}")

    memcache.add(key="worker-urls", value=validhosts, time=60 * 60 * 1)
