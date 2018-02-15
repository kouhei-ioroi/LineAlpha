# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import re
import rsa
import requests
from datetime import datetime
from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.transport import THttpClient
from thrift.protocol import TCompactProtocol
from curve import CurveThrift
from curve.ttypes import TalkException
from curve.ttypes import ToType, ContentType
try:
    import simplejson as json
except ImportError:
    import json

EMAIL_REGEX = re.compile('[^@]+@[^@]+\\.[^@]+')

class Login(object):
    LINE_DOMAIN = 'https://gd2.line.naver.jp'
    LINE_HTTP_URL = LINE_DOMAIN + '/api/v4/TalkService.do'
    LINE_HTTP_IN_URL = LINE_DOMAIN + '/P4'
    LINE_CERTIFICATE_URL = LINE_DOMAIN + '/Q'
    LINE_SESSION_LINE_URL = LINE_DOMAIN + '/authct/v1/keys/line'
    LINE_SESSION_NAVER_URL = LINE_DOMAIN + '/authct/v1/keys/naver'
    ip = '127.0.0.1'
    version = '4.1.0'
    com_name = ''
    revision = 0
    profile = None
    contacts = []
    rooms = []
    groups = []
    _session = requests.session()
    _headers = {}

    def call(callback):
        print (callback)

    def __init__(self, sid = None, password = None, callback = call, uke = None, com_name = 'siro'):
        user_agent = 'IOSIPAD 7.4.7 iPhone OS 7.0.2'
        app = 'IOSIPAD\t7.4.7\tiPhoneOS\t7.0.2'
        self._headers['User-Agent'] = user_agent
        self._headers['X-Line-Application'] = app
        self.provider = CurveThrift.Provider.LINE
        self.id = sid
        self.password = password
        self.callback = callback
        self.pcname = com_name
        self.uke = uke
        self.login()

    def login(self):
        j = self.get_json(self.LINE_SESSION_LINE_URL)
        session_key = j['session_key']
        message = (chr(len(session_key)) + session_key + chr(len(self.id)) + self.id + chr(len(self.password)) + self.password).encode(u'utf-8')
        keyname, n, e = j['rsa_key'].split(',')
        pub_key = rsa.PublicKey(int(n, 16), int(e, 16))
        crypto = rsa.encrypt(message, pub_key).encode('hex')
        self.transport = THttpClient.THttpClient(self.LINE_HTTP_URL)
        self.transport.setCustomHeaders(self._headers)
        self.protocol = TCompactProtocol.TCompactProtocol(self.transport)
        self._client = CurveThrift.Client(self.protocol)
        msg = self._client.loginWithIdentityCredentialForCertificate(self.id, self.password, keyname, crypto, False, self.ip, self.pcname, self.provider, u'')
        self._headers['X-Line-Access'] = msg.verifier
        self._pinCode = msg.pinCode
        self.callback('%s' % self._pinCode)
        j = self.get_json(self.LINE_CERTIFICATE_URL)
        self.verifier = j['result']['verifier']
        msg = self._client.loginWithVerifierForCertificate(self.verifier)
        if msg.type == 1:
            self.certificate = msg.certificate
            self.authToken = self._headers['X-Line-Access'] = msg.authToken
            self.uke('%s,%s' % (self.certificate, self.authToken))
        elif msg.type == 2:
            msg = 'require QR code'
            self.raise_error(msg)
        else:
            msg = 'require device confirm'
            self.raise_error(msg)

    def raise_error(self, msg):
        raise Exception('Error: %s' % msg)

    def get_json(self, url):
        return json.loads(self._session.get(url, headers=self._headers).text)
