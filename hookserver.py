from flask import Flask, request
from werkzeug.exceptions import HTTPException, BadRequest, Forbidden
from werkzeug.contrib.fixers import ProxyFix
from requests import get
from hmac import new
from hashlib import sha1
from ipaddress import ip_address, ip_network
from blinker import signal


class HookServer(Flask):

    def __init__(self, import_name, key=None, num_proxies=None,
                 use_signals=False):

        Flask.__init__(self, import_name)

        if num_proxies is not None:
            self.wsgi_app = ProxyFix(self.wsgi_app, num_proxies=num_proxies)

        self.config['KEY'] = key
        self.hooks = {}
        self.use_signals = use_signals

        @self.errorhandler(400)
        @self.errorhandler(403)
        @self.errorhandler(404)
        @self.errorhandler(500)
        def handle_error(e):
            if isinstance(e, HTTPException):
                msg = e.description
                status = e.code
            else:
                msg = 'Internal server error'
                status = 500
            return msg, status

        @self.before_request
        def validate_ip():
            if not self.debug:
                # Python 2.x
                if hasattr(str, 'decode'):
                    ip = ip_address(request.remote_addr.decode('utf8'))
                # Python 3.x
                else:
                    ip = ip_address(request.remote_addr)
                for block in get('https://api.github.com/meta').json()['hooks']:
                    if ip in ip_network(block):
                        break
                else:
                    raise Forbidden('Requests must originate from GitHub')

        @self.before_request
        def validate_hmac():
            if not self.debug:
                key = self.config['KEY']
                if key:
                    signature = request.headers.get('X-Hub-Signature')
                    if not signature:
                        raise BadRequest('Missing HMAC signature')
                    else:
                        payload = request.get_data()
                        digest = new(key, payload, sha1).hexdigest()
                        if ('sha1=%s' % digest) != signature:
                            raise BadRequest('Wrong HMAC signature')

        @self.route('/hooks', methods=['POST'])
        def hook():
            event = request.headers.get('X-GitHub-Event')
            if not event:
                raise BadRequest('No hook given')
            guid = request.headers.get('X-GitHub-Delivery')
            if not guid:
                raise BadRequest('No event GUID')
            data = request.get_json()
            if not data:
                raise BadRequest('No payload data')
            if self.user_signals:
                for event in ('*', event):
                    event_signal = signal(event)
                    if event_signal.receivers:
                        event_signal.send(data, guid=guid, event=event)
                return 'Hook delivered'
            else:
                if event in self.hooks:
                    return self.hooks[event](data, guid)
                else:
                    return 'Hook not used'

    def hook(self, event):
        def _wrapper(fn):
            if self.use_signals:
                event_signal = signal(event)
                event_signal.connect(fn)
            else:
                if event not in self.hooks:
                    self.hooks[event] = fn
                else:
                    raise Exception('%s hook already registered' % event)
            return fn
        return _wrapper
