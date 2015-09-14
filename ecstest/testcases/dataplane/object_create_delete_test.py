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

from boto.s3.bucket import Bucket
from boto.exception import S3ResponseError
from nose.plugins.attrib import attr
from nose.tools import eq_ as eq

from ecstest import bucketname
from ecstest import keyname
from ecstest import tag
from ecstest import testbase
from ecstest import utils
from ecstest.cephs3utils import assert_raises
from ecstest.cephs3utils import FakeWriteFile
from ecstest.cephs3utils import make_request
from ecstest.dec import not_supported
from ecstest.dec import triage
from ecstest.logger import logger


@attr(tags=[tag.DATA_PLANE, tag.OBJECT_IO])
class TestObjectCreateDelete(testbase.EcsDataPlaneTestBase):
    """
    Test the CRUD operations to bucket
    """

    def setUp(self):
        super(TestObjectCreateDelete, self).setUp(create_bucket=True)
        self.bucket_list = []

    def tearDown(self):
        for bucket in self.bucket_list:
            try:
                logger.debug("delete all keys in bucket: %s", bucket.name)
                utils.delete_keys(bucket, self.target)
                self.data_conn.delete_bucket(bucket.name)
            except Exception as err:
                logger.warn("Delete bucket exception: %s", str(err))
        super(TestObjectCreateDelete, self).tearDown()

    def _create_bucket(self, bucket_name=None):
        """
        To create bucket with bucket_name
        """
        if bucket_name is None:
            bucket_name = bucketname.get_unique_bucket_name()

        logger.debug("Create bucket: %s", bucket_name)
        bucket = self.data_conn.create_bucket(bucket_name)
        self.bucket_list.append(bucket)
        eq(isinstance(bucket, Bucket), True)

        return bucket

    def _create_keys(self, keys=[]):
        """
        Populate a (specified or new) bucket with objects with
        specified names (and contents identical to their names).
        """
        for s in keys:
            key = self.bucket.new_key(s)
            key.set_contents_from_string(s)

    def _setup_request(self, bucket_acl=None, object_acl=None):
        """
        Add a key with specified key acl to to a (new or existing) bucket.
        Then set a specified bucket acl to the bucket.
        """
        bucket = self._create_bucket()

        key_name = keyname.get_unique_key_name()
        key = bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        key = bucket.get_key(key_name)

        if bucket_acl is not None:
            bucket.set_acl(bucket_acl)
        if object_acl is not None:
            key.set_acl(object_acl)

        return bucket, key

    @triage
    # port from test case: test_object_write_file() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_write_file(self):
        """
        operation: write data from file
        assertion: succeeds and returns written data
        """
        bucket = self._create_bucket()
        key_name = keyname.get_unique_key_name()
        key = bucket.new_key(key_name)
        data = StringIO(key_name)
        key.set_contents_from_file(fp=data)

        got = key.get_contents_as_string()
        eq(got.decode('utf-8'), key_name)

    @triage
    # port from test case: test_object_copy_zero_size() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_copy_zero_size(self):
        """
        operation: copy zero sized object in same bucket
        assertion: works
        """

        key_name1 = keyname.get_unique_key_name()
        key_name2 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name1)

        fp_a = FakeWriteFile(0, '')
        key.set_contents_from_file(fp_a)
        key.copy(self.bucket, key_name2)
        key2 = self.bucket.get_key(key_name2)
        eq(key2.size, 0)

    @triage
    # port from test case: test_object_copy_same_bucket() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_copy_same_bucket(self):
        """
        operation: copy object in same bucket
        assertion: works
        """
        key_name1 = keyname.get_unique_key_name()
        key_name2 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name1)
        key.set_contents_from_string(key_name1)

        key.copy(self.bucket, key_name2)
        key2 = self.bucket.get_key(key_name2)
        eq(key2.get_contents_as_string().decode("utf-8"), key_name1)

    @triage
    # port from test case: test_object_copy_to_itself() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_copy_to_itself(self):
        """
        operation: copy object to itself
        assertion: works
        """
        key_name1 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name1)
        key.set_contents_from_string(key_name1)
        key.copy(self.bucket, key_name1)

    @triage
    # fakes3 issue: the value of metadata of key2 is None
    @not_supported('fakes3')
    # port from test case:
    #   test_object_copy_to_itself_with_metadata() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_copy_to_itself_with_metadata(self):
        """
        operation: modify object metadata by copying
        assertion: works
        """
        key_name1 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name1)
        key.set_contents_from_string(key_name1)

        key.copy(self.bucket, key_name1, {'foo': 'bar'})
        key.close()

        bucket2 = self.data_conn.get_bucket(self.bucket.name)
        key2 = bucket2.get_key(key_name1)
        md = key2.get_metadata('foo')
        eq(md, 'bar')

    @triage
    # port from test case: test_object_copy_diff_bucket() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_copy_diff_bucket(self):
        """
        operation: copy object from different bucket
        assertion: works
        """
        buckets = [self._create_bucket(), self._create_bucket()]

        key_name1 = keyname.get_unique_key_name()
        key = buckets[0].new_key(key_name1)
        key.set_contents_from_string(key_name1)
        key.copy(buckets[1], key_name1)
        key2 = buckets[1].get_key(key_name1)
        eq(key2.get_contents_as_string().decode("utf-8"), key_name1)

    @triage
    # port from test case: test_object_copy_canned_acl() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_copy_canned_acl(self):
        """
        operation: copy object and change acl
        assertion: works
        """
        key_name1 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name1)
        key.set_contents_from_string(key_name1)

        # use COPY directive
        key_name2 = keyname.get_unique_key_name()
        key2 = self.bucket.copy_key(key_name2, self.bucket.name, key_name1,
                                    headers={'x-amz-acl': 'public-read'})
        res = make_request(self.data_conn, 'GET', self.bucket, key2)
        # ECS return 400
        eq(res.status, 200)
        eq(res.reason, 'OK')

        # use REPLACE directive
        key_name3 = keyname.get_unique_key_name()
        key3 = self.bucket.copy_key(key_name3, self.bucket.name, key_name1,
                                    headers={'x-amz-acl': 'public-read'},
                                    metadata={'abc': 'def'})
        res = make_request(self.data_conn, 'GET', self.bucket, key3)
        eq(res.status, 200)
        eq(res.reason, 'OK')

    @triage
    # fakes3 issue: the first letter of the key of metadata was capitalized
    @not_supported('fakes3')
    # port from test case: test_object_copy_retaining_metadata() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_copy_retaining_metadata(self):
        """
        operation: copy object and retain metadata
        assertion: works
        """

        key_name1 = keyname.get_unique_key_name()
        key_name2 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name1)

        metadata = {'key1': 'value1', 'key2': 'value2'}
        key.set_metadata('key1', 'value1')
        key.set_metadata('key2', 'value2')
        content_type = 'audio/ogg'
        key.content_type = content_type
        key.set_contents_from_string(key_name1)

        self.bucket.copy_key(key_name2, self.bucket.name, key_name1)
        key2 = self.bucket.get_key(key_name2)

        eq(key2.size, len(key_name1))
        eq(key2.metadata, metadata)
        eq(key2.content_type, content_type)

    @triage
    # fakes3 issue: the first letter of the key of metadata was capitalized
    @not_supported('fakes3')
    # port from test case: test_object_copy_replacing_metadata() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_copy_replacing_metadata(self):
        """
        operation: copy object and replace metadata
        assertion: works
        """

        key_name1 = keyname.get_unique_key_name()
        key_name2 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name1)

        key.set_metadata('key1', 'value1')
        key.set_metadata('key2', 'value2')
        key.content_type = 'audio/ogg'
        key.set_contents_from_string(key_name1)

        metadata = {'key3': 'value3', 'key1': 'value4'}
        content_type = 'audio/mpeg'
        self.bucket.copy_key(key_name2, self.bucket.name, key_name1,
                             metadata=metadata,
                             headers={'Content-Type': content_type})
        key2 = self.bucket.get_key(key_name2)

        eq(key2.size, len(key_name1))
        eq(key2.metadata, metadata)
        eq(key2.content_type, content_type)

    @triage
    # ecs returns 400 when 'GET' request
    @not_supported('ecs')
    # port from test case: test_object_raw_get() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_get(self):
        """
        operation: get a object from bucket
        assertion: bucket is readable
        """
        bucket, key = self.self._setup_request('public-read', 'public-read')

        res = make_request(self.data_conn, 'GET', bucket, key)
        # ecs returns 400
        eq(res.status, 200)
        eq(res.reason, 'OK')

    @triage
    # ecs returns 400 when 'GET' request
    @not_supported('ecs')
    # port from test case: test_object_raw_get_bucket_gone() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_get_bucket_gone(self):
        """
        operation: delete object from a gone bucket
        assertion: fail with 404 error
        """
        bucket, key = self.self._setup_request('public-read', 'public-read')
        key.delete()
        bucket.delete()

        res = make_request(self.data_conn, 'GET', bucket, key)
        # ecs returns 400
        eq(res.status, 404)
        eq(res.reason, 'Not Found')

    @triage
    # fakes3 returns 200 OK when key.delete
    @not_supported('fakes3')
    # port from test case: test_object_delete_key_bucket_gone() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_delete_key_bucket_gone(self):
        """
        operation: delete object from a gone bucket
        assertion: fail with 404 error
        """
        bucket, key = self.self._setup_request()
        key.delete()
        bucket.delete()

        e = assert_raises(S3ResponseError, key.delete)
        # fakes3 returns 200 OK
        eq(e.status, 404)
        eq(e.reason, 'Not Found')
        eq(e.error_code, 'NoSuchBucket')

    @triage
    # ecs returns 400 when 'GET' request
    @not_supported('ecs')
    # port from test case: test_object_raw_get_object_gone() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_get_object_gone(self):
        """
        operation: get a gone object
        assertion: fail with 404 error
        """
        bucket, key = self.self._setup_request('public-read', 'public-read')
        key.delete()

        res = make_request(self.data_conn, 'GET', bucket, key)
        # ecs returns 400
        eq(res.status, 404)
        eq(res.reason, 'Not Found')

    @triage
    # ecs returns 400 when 'GET' request
    @not_supported('ecs')
    # port from test case: test_object_raw_get_bucket_acl() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_get_bucket_acl(self):
        """
        operation: unauthenticated on private bucket
        assertion: success
        """
        bucket, key = self._setup_request('private', 'public-read')

        res = make_request(self.data_conn, 'GET', bucket, key)
        # ecs returns 400
        eq(res.status, 200)
        eq(res.reason, 'OK')

    @triage
    # fakes3 returns 200 OK when 'GET' request
    @not_supported('fakes3')
    # port from test case: test_object_raw_get_object_acl() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_get_object_acl(self):
        """
        operation: unauthenticated on private object
        assertion: fail with 403 error
        """
        bucket, key = self._setup_request('public-read', 'private')

        res = make_request(self.data_conn, 'GET', bucket, key)
        # ecs returns 400, fakes3 returns 200 OK
        eq(res.status, 403)
        eq(res.reason, 'Forbidden')

    @triage
    # port from test case: test_object_raw_authenticated() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_authenticated(self):
        """
        operation: authenticated on public bucket/object
        assertion: success
        """
        bucket, key = self._setup_request('public-read', 'public-read')

        res = make_request(self.data_conn, 'GET', bucket, key,
                           authenticated=True)
        eq(res.status, 200)
        eq(res.reason, 'OK')

    @triage
    # fakes3 gets incorrect response headers
    @not_supported('fakes3')
    # port from test case: test_object_raw_response_headers() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_response_headers(self):
        """
        operation: authenticated on private bucket/private object with modified
                   response headers
        assertion: success
        """
        bucket, key = self._setup_request('private', 'private')

        response_headers = {
            'response-content-type': 'foo/bar',
            'response-content-disposition': 'bla',
            'response-content-language': 'esperanto',
            'response-content-encoding': 'aaa',
            'response-expires': '123',
            'response-cache-control': 'no-cache',
        }

        res = make_request(self.data_conn, 'GET', bucket, key,
                           authenticated=True,
                           response_headers=response_headers)
        eq(res.status, 200)
        eq(res.reason, 'OK')
        # fakes3 returns 'application/octet-stream'
        eq(res.getheader('content-type'), 'foo/bar')
        # fakes3 returns None
        eq(res.getheader('content-disposition'), 'bla')
        # fakes3 returns None
        eq(res.getheader('content-language'), 'esperanto')
        # fakes3 returns None
        eq(res.getheader('content-encoding'), 'aaa')
        # fakes3 returns None
        eq(res.getheader('expires'), '123')
        # fakes3 returns None
        eq(res.getheader('cache-control'), 'no-cache')

    @triage
    # port from test case:
    #   test_object_raw_authenticated_bucket_acl() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_authenticated_bucket_acl(self):
        """
        operation: authenticated on private bucket/public object
        assertion: success
        """
        bucket, key = self._setup_request('private', 'public-read')

        res = make_request(self.data_conn, 'GET', bucket, key,
                           authenticated=True)
        eq(res.status, 200)
        eq(res.reason, 'OK')

    @triage
    # port from test case:
    #   test_object_raw_authenticated_object_acl() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_authenticated_object_acl(self):
        """
        operation: authenticated on public bucket/private object
        assertion: success
        """
        bucket, key = self._setup_request('public-read', 'private')

        res = make_request(self.data_conn, 'GET', bucket, key,
                           authenticated=True)
        eq(res.status, 200)
        eq(res.reason, 'OK')

    @triage
    # port from test case:
    #   test_object_raw_authenticated_bucket_gone() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_authenticated_bucket_gone(self):
        """
        operation: authenticated on deleted object and bucket
        assertion: fail with 404 error
        """
        bucket, key = self._setup_request('public-read', 'public-read')
        key.delete()
        bucket.delete()

        res = make_request(self.data_conn, 'GET', bucket, key,
                           authenticated=True)
        eq(res.status, 404)
        eq(res.reason, 'Not Found')

    @triage
    # port from test case:
    #   test_object_raw_authenticated_object_gone() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_authenticated_object_gone(self):
        """
        operation: authenticated on deleted object
        assertion: fail with 404 error
        """
        bucket, key = self._setup_request('public-read', 'public-read')
        key.delete()

        res = make_request(self.data_conn, 'GET', bucket, key,
                           authenticated=True)
        eq(res.status, 404)
        eq(res.reason, 'Not Found')

    @triage
    # ecs returns 400 when 'PUT' request
    # fakes3 returns 200 OK when 'PUT' request
    @not_supported('ecs', 'fakes3')
    # port from test case: test_object_raw_put() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_put(self):
        """
        operation: unauthenticated and no object acls
        assertion: fail with 403 error
        """
        bucket = self._create_bucket()
        key = bucket.new_key('foo')

        res = make_request(self.data_conn, 'PUT', bucket, key, body='foo')
        # ecs returns 400, fakes3 returns 200 OK
        eq(res.status, 403)
        eq(res.reason, 'Forbidden')

    @triage
    # ecs returns 400 when 'PUT' request
    @not_supported('ecs')
    # port from test case: test_object_raw_put_write_access() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_put_write_access(self):
        """
        operation: unauthenticated and publically writable object
        assertion: success
        """
        bucket = self._create_bucket()
        bucket.set_acl('public-read-write')
        key = bucket.new_key('foo')

        res = make_request(self.data_conn, 'PUT', bucket, key, body='foo')
        # ecs returns 400
        eq(res.status, 200)
        eq(res.reason, 'OK')

    @triage
    # port from test case: test_object_raw_put_authenticated() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_put_authenticated(self):
        """
        operation: authenticated and no object acls
        assertion: success
        """
        bucket = self._create_bucket()
        key = bucket.new_key('foo')

        res = make_request(self.data_conn, 'PUT', bucket, key, body='foo',
                           authenticated=True)
        eq(res.status, 200)
        eq(res.reason, 'OK')

    @triage
    # fakes3 returns 200 OK when 'GET' request
    @not_supported('fakes3')
    # port from test case:
    #   test_object_raw_put_authenticated_expired() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_raw_put_authenticated_expired(self):
        """
        operation: authenticated and no object acls
        assertion: success
        """
        bucket = self._create_bucket()
        key = bucket.new_key('foo')

        res = make_request(self.data_conn, 'PUT', bucket, key, body='foo',
                           authenticated=True, expires_in=-1000)
        # fakes3 returns 200 OK
        eq(res.status, 403)
        eq(res.reason, 'Forbidden')
