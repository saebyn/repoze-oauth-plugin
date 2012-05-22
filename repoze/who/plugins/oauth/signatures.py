import base64
import urllib
import time
import random
import urlparse
import hmac
import binascii
import httplib2

try:
    from urlparse import parse_qs
    parse_qs # placate pyflakes
except ImportError:
    # fall back for Python 2.5
    from cgi import parse_qs

try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    # hashlib was added in Python 2.5
    import sha

try:
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import long_to_bytes, bytes_to_long
except ImportError:
    RSA=None


from oauth2 import SignatureMethod


class SignatureMethod_RSA_SHA1(SignatureMethod):
    name = 'RSA-SHA1'

    def signing_base(self, request, consumer, token):
        if request.normalized_url is None:
            raise ValueError("Base URL for request is not set.")

        sig = (
            escape(request.method),
            escape(request.normalized_url),
            escape(request.get_normalized_parameters()),
        )

        key = consumer.secret
        raw = '&'.join(sig)
        return key, raw

    def sign(self, request, consumer, token):
        """Builds the base signature string."""
        if RSA is None: raise NotImplementedError, self.name
        key, raw = self.signing_base(request, consumer, token)
        
        digest = sha(raw).digest()
        sig = key.sign(self._pkcs1imify(key, digest), '')[0]
        sig_bytes = long_to_bytes(sig)
        # Calculate the digest base 64.
        return binascii.b2a_base64(sig_bytes)[:-1]

    def check(self, request, consumer, token, signature):
        """Returns whether the given signature is the correct signature for
        the given consumer and token signing the given request."""
        if RSA is None: raise NotImplementedError, self.name
        key, raw = self.signing_base(request, consumer, token)

        digest = sha(raw).digest()
        sig = bytes_to_long(binascii.a2b_base64(signature))
        data = self._pkcs1imify(key, digest)
        
        pubkey = key.publickey()
        return pubkey.verify(data, (sig,))

    @staticmethod
    def _pkcs1imify(key, data):
        """Adapted from paramiko

        turn a 20-byte SHA1 hash into a blob of data as large as the key's N,
        using PKCS1's \"emsa-pkcs1-v1_5\" encoding.  totally bizarre.
        """
        SHA1_DIGESTINFO = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
        size = len(long_to_bytes(key.n))
        filler = '\xff' * (size - len(SHA1_DIGESTINFO) - len(data) - 3)
        return '\x00\x01' + filler + '\x00' + SHA1_DIGESTINFO + data
        

