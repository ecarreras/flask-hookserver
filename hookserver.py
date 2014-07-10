from flask import Flask, request
from werkzeug.exceptions import HTTPException, BadRequest, Forbidden
from werkzeug.contrib.fixers import ProxyFix
from requests import get
from hmac import new
from hashlib import sha1
from ipaddress import ip_address, ip_network

class HookServer(Flask):

    def __init__(self, import_name, key, num_proxies=None):

        Flask.__init__(self, import_name)

        if num_proxies is not None:
            self.wsgi_app = ProxyFix(self.wsgi_app, num_proxies=num_proxies)

        self.config['KEY'] = key
        self.hooks = {}

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
                signature = request.headers.get('X-Hub-Signature')
                if not signature:
                    raise BadRequest('Missing HMAC signature')
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
            if event in self.hooks:
                return self.hooks[event](data, guid)
            else:
                return 'Hook not used'

    def hook(self, hook_name):
        def _wrapper(fn):
            if hook_name not in self.hooks:
                self.hooks[hook_name] = fn
            else:
                raise Exception('%s hook already registered' % hook_name)
            return fn
        return _wrapper
