# __CR__
# Copyright (c) 2008-2015 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.
# __CR__

'''
Author: Rubicon ISE team
'''
from io import StringIO
from http.client import HTTPConnection, HTTPSConnection
import operator
import os
import random
import string
from urllib.parse import urlparse

import boto
from nose.tools import eq_ as eq


def assert_raises(excClass, callableObj, *args, **kwargs):
    """
    like unittest.TestCase.assertRaises, but return the exception.
    """
    try:
        callableObj(*args, **kwargs)
    except excClass as e:
        return e
    else:
        if hasattr(excClass, '__name__'):
            excName = excClass.__name__
        else:
            excName = str(excClass)
        raise AssertionError("%s not raised" % excName)


# port from function: check_access_denied() of https://github.com/ceph/
#   s3-tests/blob/master/s3tests/functional/test_s3.py
def check_access_denied(fn, *args, **kwargs):
    """
    Verify an 'AccessDenied' error returned when function send a request to s3
    """
    e = assert_raises(boto.exception.S3ResponseError, fn, *args, **kwargs)
    eq(e.status, 403)
    eq(e.reason, 'Forbidden')
    eq(e.error_code, 'AccessDenied')


# port from function: check_grants() of https://github.com/ceph/
#   s3-tests/blob/master/s3tests/functional/test_s3.py
def check_grants(got, want):
    """
    Check that grants list in got matches the dictionaries in want,
    in any order.
    """
    eq(len(got), len(want))

    # In Python 3 any attempts at ordering NoneType instances result in an
    # exception. The quickest fix is to explicitly map None instances into
    # sortable something like "".
    for grant in got:
        grant.id = grant.id if grant.id else ""
    for grant in want:
        grant["id"] = grant["id"] if grant["id"] else ""

    got = sorted(got, key=operator.attrgetter('id'))
    want = sorted(want, key=operator.itemgetter('id'))
    for g, w in zip(got, want):
        w = dict(w)
        eq(g.permission, w.pop('permission'))
        eq(g.id, w.pop('id'))
        eq(g.display_name, w.pop('display_name'))
        eq(g.uri, w.pop('uri'))
        eq(g.email_address, w.pop('email_address'))
        eq(g.type, w.pop('type'))
        eq(w, {})


def create_keys(bucket, keys=[]):
    """
    Populate a (specified or new) bucket with objects with
    specified names (and contents identical to their names).
    """
    for s in keys:
        key = bucket.new_key(s)
        key.set_contents_from_string(s)


# port from function: _make_bucket_request() of https://github.com/ceph/
#   s3-tests/blob/master/s3tests/functional/test_s3.py
def make_request(conn, method, bucket, key, body=None,
                 authenticated=False,
                 response_headers=None,
                 expires_in=100000):
    """
    issue a request for a specified method, on a specified bucket,
    with a specified (optional) body (encrypted per the connection), and
    return the response (status, reason)
    """

    if authenticated:
        url = key.generate_url(expires_in,
                               method=method,
                               response_headers=response_headers)
        o = urlparse(url)
        path = o.path + '?' + o.query
    else:
        path = '/{bucket}/{obj}'.format(bucket=key.bucket.name, obj=key.name)

    if conn.is_secure:
        connect = HTTPSConnection
    else:
        connect = HTTPConnection

    _conn = connect(conn.host, conn.port)
    _conn.request(method, path, body=body)
    res = _conn.getresponse()

    return res


def gen_rand_string(size, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def do_test_multipart_upload_contents(bucket, key_name, num_parts):
    payload = gen_rand_string(5)*1024*1024
    mp = bucket.initiate_multipart_upload(key_name)
    for i in range(0, num_parts):
        mp.upload_part_from_file(StringIO(payload), i+1)

    last_payload = '123'*1024*1024
    mp.upload_part_from_file(StringIO(last_payload), num_parts + 1)
    mp.complete_upload()

    key = bucket.get_key(key_name)
    test_string = key.get_contents_as_string()

    all_payload = payload*num_parts + last_payload

    eq(test_string.decode('utf-8'), all_payload)
    return all_payload


class FakeFile(object):
    """
    file that simulates seek, tell, and current character
    """
    def __init__(self, char='A', interrupt=None):
        self.offset = 0
        self.char = char
        self.interrupt = interrupt

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self.offset = offset
        elif whence == os.SEEK_END:
            self.offset = self.size + offset
        elif whence == os.SEEK_CUR:
            self.offset += offset

    def tell(self):
        return self.offset


class FakeWriteFile(FakeFile):
    """
    file that simulates interruptable reads of constant data
    """
    def __init__(self, size, char='A', interrupt=None):
        FakeFile.__init__(self, char, interrupt)
        self.size = size

    def read(self, size=-1):
        if size < 0:
            size = self.size - self.offset
        count = min(size, self.size - self.offset)
        self.offset += count

        # Sneaky! do stuff before we return (the last time)
        if self.interrupt is not None \
                and self.offset == self.size and count > 0:
            self.interrupt()

        return self.char*count


class FakeReadFile(FakeFile):
    """
    file that simulates writes, interrupting after the second
    """
    def __init__(self, size, char='A', interrupt=None):
        FakeFile.__init__(self, char, interrupt)
        self.interrupted = False
        self.size = 0
        self.expected_size = size

    def write(self, chars):
        if isinstance(chars, bytes):
            chars = chars.decode('utf-8')

        eq(chars, self.char*len(chars))

        self.offset += len(chars)
        self.size += len(chars)

        # Sneaky! do stuff on the second seek
        if not self.interrupted and self.interrupt is not None \
                and self.offset > 0:
            self.interrupt()
            self.interrupted = True

    def close(self):
        eq(self.size, self.expected_size)


class FakeFileVerifier(object):
    """
    file that verifies expected data has been written
    """
    def __init__(self, char=None):
        self.char = char
        self.size = 0

    def write(self, data):
        if isinstance(data, bytes):
            data = data.decode('utf-8')

        size = len(data)
        if self.char is None:
            self.char = str(data[0])
        self.size += size
        eq(data, self.char*size)
