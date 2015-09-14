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

from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse
from io import StringIO
import string
import random

from boto.s3.multipart import MultiPartUpload
from boto.exception import S3ResponseError
from nose.plugins.attrib import attr
from nose.tools import eq_ as eq

from ecstest import keyname
from ecstest import tag
from ecstest import testbase
from ecstest.cephs3utils import assert_raises
from ecstest.dec import not_supported
from ecstest.dec import triage


def generate_random(size, part_size=5*1024*1024):
    """
    Generate the specified number random data.
    (actually each MB is a repetition of the first KB)
    """
    chunk = 1024
    allowed = string.ascii_letters
    for x in range(0, size, part_size):
        strpart = ''.join([allowed[random.randint(0, len(allowed) - 1)]
                           for _ in range(chunk)])
        s = ''
        left = size - x
        this_part_size = min(left, part_size)
        for y in range(int(this_part_size / chunk)):
            s += strpart

        s += strpart[:(this_part_size % chunk)]
        yield s
        if x == size:
            return


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


@attr(tags=[tag.DATA_PLANE, tag.OBJECT_IO])
class TestObjectMultipart(testbase.EcsDataPlaneTestBase):
    """
    Test the operations to multipart uploading
    """

    def setUp(self):
        super(TestObjectMultipart, self).setUp(create_bucket=True)

    def tearDown(self):
        super(TestObjectMultipart, self).tearDown()

    # port from function: _make_bucket_request() of https://github.com/ceph/
    #   s3-tests/blob/master/s3tests/functional/test_s3.py
    def _make_bucket_request(self, method, bucket, body=None,
                             authenticated=False, expires_in=100000):
        """
        issue a request for a specified method, on a specified bucket,
        with a specified (optional) body (encrypted per the connection), and
        return the response (status, reason)
        """
        if authenticated:
            url = bucket.generate_url(expires_in, method=method)
            url = urlparse(url)
            path = url.path + '?' + url.query
        else:
            path = '/{bucket}'.format(bucket=bucket.name)

        if self.data_conn.is_secure:
            connect = HTTPSConnection
        else:
            connect = HTTPConnection

        conn = connect(self.data_conn.host, self.data_conn.port)
        conn.request(method, path, body=body)
        res = conn.getresponse()

        return res

    # port from function: _head_bucket() of https://github.com/ceph/s3-tests/
    #   blob/master/s3tests/functional/test_s3.py
    def _head_bucket(self, bucket, authenticated=True):
        res = self._make_bucket_request('HEAD',
                                        bucket,
                                        authenticated=authenticated)
        eq(res.status, 200)
        eq(res.reason, 'OK')

        result = {}

        obj_count = res.getheader('x-rgw-object-count')
        if obj_count is not None:
            result['x-rgw-object-count'] = int(obj_count)

        bytes_used = res.getheader('x-rgw-bytes-used')
        if bytes_used is not None:
            result['x-rgw-bytes-used'] = int(bytes_used)

        return result

    def transfer_part(self, mp_id, mp_keyname, i, part):
        """
        Transfer a part of a multipart upload. Designed to be run in parallel.
        """
        mp = MultiPartUpload(self.bucket)
        mp.key_name = mp_keyname
        mp.id = mp_id
        part_out = StringIO(part)
        mp.upload_part_from_file(part_out, i+1)

    def multipart_upload(self, key_name, size, part_size=5*1024*1024,
                         do_list=None, headers=None, metadata=None):
        """
        generate a multi-part upload for a random file of specifed size,
        if requested, generate a list of the parts
        return the upload descriptor
        """
        upload = self.bucket.initiate_multipart_upload(key_name,
                                                       headers=headers,
                                                       metadata=metadata)

        for i, part in enumerate(generate_random(size, part_size)):
            self.transfer_part(upload.id, upload.key_name, i, part)

        if do_list is not None:
            self.bucket.list_multipart_uploads()

        return upload

    @triage
    # fakes3 returns 500 Internal Server Error when upload.complete_upload
    # ecs returns 400 InvalidRequest when upload.complete_upload
    @not_supported('fakes3', 'ecs')
    # port from test case: test_multipart_upload_empty() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_multipart_upload_empty(self):
        """
        operation: check multipart upload without parts
        assertion: fails with 404 error
        """
        key_name = keyname.get_unique_key_name()
        upload = self.multipart_upload(key_name, 0)

        e = assert_raises(S3ResponseError, upload.complete_upload)

        # fakes3 returns 500
        eq(e.status, 400)

        # ecs returns 'InvalidRequest'
        eq(e.error_code, u'MalformedXML')

    @triage
    # fakes3 ValueError issue: fakes3 gets ValueError('Empty key names are
    #   not allowed') when transfer_part() in upload.complete_upload()
    @not_supported('fakes3')
    # port from test case: test_multipart_upload_small() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_multipart_upload_small(self):
        """
        operation: check multipart uploads with single small part
        assertion: success
        """
        key_name = keyname.get_unique_key_name()
        upload = self.multipart_upload(key_name, size=1)
        upload.complete_upload()

        key = self.bucket.get_key(key_name)
        eq(key.size, 1)

    @triage
    @not_supported('fakes3')  # fakes3 ValueError issue
    # port from test case: test_multipart_upload() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_multipart_upload(self):
        """
        operation: complete multi-part upload
        assertion: success
        """
        key_name = keyname.get_unique_key_name()
        content_type = 'text/bla'

        upload = self.multipart_upload(key_name,
                                       size=30 * 1024,
                                       headers={'Content-Type': content_type},
                                       metadata={'foo': 'bar'})
        upload.complete_upload()

        result = self._head_bucket(self.bucket)

        eq(result.get('x-rgw-object-count', 1), 1)
        eq(result.get('x-rgw-bytes-used', 30 * 1024), 30 * 1024)

        key = self.bucket.get_key(key_name)
        eq(key.metadata['foo'], 'bar')
        eq(key.content_type, content_type)

    @triage
    @not_supported('fakes3')  # fakes3 ValueError issue
    # port from test case: test_multipart_upload_multiple_sizes() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_multipart_upload_multiple_sizes(self):
        """
        operation: complete multiple multi-part upload with different sizes
        assertion: success
        """
        key_name = keyname.get_unique_key_name()

        upload = self.multipart_upload(key_name, 5 * 1024)
        upload.complete_upload()

        upload = self.multipart_upload(key_name, 5 * 1024 + 100)
        upload.complete_upload()

        upload = self.multipart_upload(key_name, 5 * 1024 + 600)
        upload.complete_upload()

        upload = self.multipart_upload(key_name, 10 * 1024 + 100)
        upload.complete_upload()

        upload = self.multipart_upload(key_name, 10 * 1024 + 600)
        upload.complete_upload()

        upload = self.multipart_upload(key_name, 10 * 1024)
        upload.complete_upload()

    @triage
    # ecs does not return S3ResponseError when upload.complete_upload
    @not_supported('fakes3', 'ecs')  # fakes3 ValueError issue
    # port from test case: test_multipart_upload_size_too_small() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_multipart_upload_size_too_small(self):
        """
        operation: check failure on multiple multi-part upload
                   with size too small
        assertion: fails with 404 error
        """
        key_name = keyname.get_unique_key_name()

        upload = self.multipart_upload(key_name, 100 * 1024, part_size=10*1024)
        e = assert_raises(S3ResponseError, upload.complete_upload)
        eq(e.status, 400)
        eq(e.error_code, u'EntityTooSmall')

    @triage
    @not_supported('fakes3')  # fakes3 ValueError issue
    # port from test case: test_multipart_upload_contents() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_multipart_upload_contents(self):
        """
        operation: check contents of multi-part upload
        assertion: success
        """
        key_name = keyname.get_unique_key_name()
        payload = gen_rand_string(5)*1024*1024

        mp = self.bucket.initiate_multipart_upload(key_name)
        num_parts = 3
        for i in range(0, num_parts):
            mp.upload_part_from_file(StringIO(payload), i+1)

        last_payload = '123'*1024*1024
        mp.upload_part_from_file(StringIO(last_payload), num_parts + 1)

        mp.complete_upload()

        key = self.bucket.get_key(key_name)
        test_string = key.get_contents_as_string()
        eq(test_string.decode('utf-8'), payload*num_parts + last_payload)

    @triage
    @not_supported('fakes3')  # fakes3 ValueError issue
    # port from test case:
    #   test_multipart_upload_overwrite_existing_object() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_multipart_upload_overwrite_existing_object(self):
        """
        operation: multi-part upload overwrites existing key
        assertion: success
        """
        key_name = keyname.get_unique_key_name()
        payload = gen_rand_string(5)*1024*1025

        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(payload)

        mp = self.bucket.initiate_multipart_upload(key_name)

        num_parts = 2
        for i in range(0, num_parts):
            mp.upload_part_from_file(StringIO(payload), i+1)

        mp.complete_upload()

        key = self.bucket.get_key(key_name)
        test_string = key.get_contents_as_string()
        eq(test_string.decode('utf-8'), payload*num_parts)

    @triage
    # ecs returns S3ResponseError 200 OK when upload.cancel_upload()
    @not_supported('fakes3', 'ecs')  # fakes3 ValueError issue
    # port from test case: test_abort_multipart_upload() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_abort_multipart_upload(self):
        """
        operation: abort multi-part upload
        assertion: success
        """
        key_name = keyname.get_unique_key_name()
        upload = self.multipart_upload(key_name, 10 * 1024 * 1024)

        # ecs returns boto exception, but status still is 200 OK
        upload.cancel_upload()

        result = self._head_bucket(self.bucket)

        eq(result.get('x-rgw-object-count', 0), 0)
        eq(result.get('x-rgw-bytes-used', 0), 0)

    @triage
    # fakes3 does not return S3ResponseError when cancel_multipart_upload
    @not_supported('fakes3')
    # port from test case: test_abort_multipart_upload_not_found() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_abort_multipart_upload_not_found(self):
        """
        operation: abort multi-part upload with invalid upload_id
        assertion: fails with 404 error
        """
        key_name = keyname.get_unique_key_name()
        e = assert_raises(S3ResponseError, self.bucket.cancel_multipart_upload,
                          key_name, '1')
        eq(e.status, 404)
        eq(e.reason, 'Not Found')
        eq(e.error_code, 'NoSuchUpload')

    @triage
    # ecs returns S3ResponseError 200 OK when upload.cancel_upload()
    @not_supported('fakes3', 'ecs')  # fakes3 ValueError issue
    # port from test case: test_list_multipart_upload() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_list_multipart_upload(self):
        """
        operation: concurrent multi-part uploads
        assertion: success
        """
        key_name = keyname.get_unique_key_name()
        mb = 1024 * 1024
        upload1 = self.multipart_upload(key_name, 5 * mb, do_list=True)
        upload2 = self.multipart_upload(key_name, 6 * mb, do_list=True)

        key_name2 = keyname.get_unique_key_name()
        upload3 = self.multipart_upload(key_name2, 5 * mb, do_list=True)

        l = self.bucket.list_multipart_uploads()
        l = list(l)

        index = dict([(key_name, 2), (key_name2, 1)])

        for upload in l:
            index[upload.key_name] -= 1

        for k, c in index.items():
            eq(c, 0)

        # ecs returns boto exception, but status still is 200 OK
        upload1.cancel_upload()
        upload2.cancel_upload()
        upload3.cancel_upload()
