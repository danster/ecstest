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
from ecstest.cephs3utils import create_keys
from ecstest.dec import not_supported
from ecstest.dec import triage
from ecstest.logger import logger


@attr(tags=[tag.DATA_PLANE, tag.BUCKET_MGMT])
class TestBucketAccess(testbase.EcsDataPlaneTestBase):
    """
    Access a bucket with several conditions and test the result of response
    """

    def setUp(self):
        super(TestBucketAccess, self).setUp()
        self.bucket_list = []

    def tearDown(self):
        for bucket in self.bucket_list:
            try:
                logger.debug("delete all keys in bucket: %s", bucket.name)
                utils.delete_keys(bucket, self.target)
                self.data_conn.delete_bucket(bucket.name)
            except Exception as err:
                logger.warn("Delete bucket exception: %s", str(err))
        super(TestBucketAccess, self).tearDown()

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

    @triage
    # port from test case: test_bucket_notexist() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_not_exist(self):
        """
        operation: get a non-existent bucket
        assertion: fails with 404 error
        """
        # generate a (hopefully) unique, not-yet existent bucket name
        bucket_name = bucketname.get_unique_bucket_name()

        e = assert_raises(S3ResponseError,
                          self.data_conn.get_bucket,
                          bucket_name)

        eq(e.status, 404)
        eq(e.reason, 'Not Found')
        eq(e.error_code, 'NoSuchBucket')

    @triage
    # fakes3 return: '500 Internal Server Error'
    @not_supported('fakes3')
    # port from test case: test_bucket_delete_notexist() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_delete_not_exist(self):
        """
        operation: delete a non-existent bucket
        assertion: fails with 404 error
        """
        bucket_name = bucketname.get_unique_bucket_name()

        e = assert_raises(S3ResponseError,
                          self.data_conn.delete_bucket,
                          bucket_name)
        eq(e.status, 404)
        eq(e.reason, 'Not Found')
        eq(e.error_code, 'NoSuchBucket')

    @triage
    # fakes3 return: '500 Internal Server Error'
    @not_supported('fakes3')
    # port from test case: test_bucket_delete_nonempty() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_delete_not_empty(self):
        """
        operation: delete a non-empty bucket
        assertion: fails with 404 error
        """
        bucket = self._create_bucket()

        # fill up bucket
        key_name = keyname.get_unique_key_name()
        key = bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        # try to delete
        e = assert_raises(S3ResponseError, bucket.delete)
        eq(e.status, 409)
        eq(e.reason, 'Conflict')
        eq(e.error_code, 'BucketNotEmpty')

    @triage
    # fakes3: the exception doesn't be raised when key.set_contents_from_string
    @not_supported('fakes3')
    # port from test case: test_object_write_to_nonexist_bucket() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_write_to_not_exist_bucket(self):
        """
        operation: write a object a non-existent bucket
        assertion: fails with 404 error
        """
        bucket_name = bucketname.get_unique_bucket_name()
        bucket = self.data_conn.get_bucket(bucket_name, validate=False)

        key_name = keyname.get_unique_key_name()
        key = bucket.new_key(key_name)
        e = assert_raises(S3ResponseError,
                          key.set_contents_from_string,
                          key_name)
        eq(e.status, 404)
        eq(e.reason, 'Not Found')
        eq(e.error_code, 'NoSuchBucket')

    @triage
    # fakes3 return: '500 Internal Server Error'
    @not_supported('fakes3')
    # port from test case: test_bucket_create_delete() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_delete_deleted_bucket(self):
        """
        operation: delete a deleted bucket
        assertion: fails with 404 error
        """
        bucket = self._create_bucket()
        # make sure it's actually there
        self.data_conn.get_bucket(bucket.name)
        bucket.delete()
        # make sure it's gone
        e = assert_raises(S3ResponseError, bucket.delete)
        eq(e.status, 404)
        eq(e.reason, 'Not Found')
        eq(e.error_code, 'NoSuchBucket')

    @triage
    # port from test cases:
    #   test_bucket_head() and test_bucket_head_extended() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_head(self):
        """
        operation: read bucket extended information
        assertion: extended information is getting updated
        """
        bucket = self._create_bucket()
        result = self._head_bucket(bucket)

        eq(result.get('x-rgw-object-count', 0), 0)
        eq(result.get('x-rgw-bytes-used', 0), 0)

        keyname1 = keyname.get_unique_key_name()
        keyname2 = keyname.get_unique_key_name()
        keyname3 = keyname.get_unique_key_name()

        create_keys(bucket, keys=[keyname1, keyname2, keyname3])
        result = self._head_bucket(bucket)

        eq(result.get('x-rgw-object-count', 3), 3)
        length = len(keyname1) + len(keyname2) + len(keyname3)
        assert result.get('x-rgw-bytes-used', length) > 0

    @triage
    # ecs returns '501 Not Implemented' when bucket.enable_loggin()
    @not_supported('fakes3', 'ecs')  # fakes3 bucket acl issue
    # port from test case: test_logging_toggle() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_logging_toggle(self):
        """
        operation: set/enable/disable logging target
        assertion: operations succeed
        """

        bucket = self._create_bucket()
        log_bucket = self._create_bucket(bucket.name + '-log')
        log_bucket.set_as_logging_target()

        # ecs returns '501 Not Implemented'
        bucket.enable_logging(target_bucket=log_bucket,
                              target_prefix=bucket.name)
        bucket.disable_logging()
