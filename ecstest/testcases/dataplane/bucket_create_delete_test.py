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

from boto.exception import S3ResponseError
from boto.s3.bucket import Bucket
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
class TestBucketCreateDelete(testbase.EcsDataPlaneTestBase):
    """
    Test the CRUD operations to bucket
    """

    def setUp(self):
        super(TestBucketCreateDelete, self).setUp()
        self.bucket_list = []

    def tearDown(self):
        for bucket in self.bucket_list:
            try:
                logger.debug("delete all keys in bucket: %s", bucket.name)
                utils.delete_keys(bucket, self.target)
                self.data_conn.delete_bucket(bucket.name)
            except Exception as err:
                logger.warn("Delete bucket exception: %s", str(err))
        super(TestBucketCreateDelete, self).tearDown()

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

    # port from function: check_bad_bucket_name() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def check_bad_bucket_name(self, name):
        """
        Attempt to create a bucket with a specified name, and confirm
        that the request fails because of an invalid bucket name.
        """
        e = assert_raises(S3ResponseError,
                          self._create_bucket,
                          name)
        print(e.status, e.reason, e.error_code)
        eq(e.status, 400)
        eq(e.reason, 'Bad Request')
        eq(e.error_code, 'InvalidBucketName')

    # port from function: check_good_bucket_name() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def check_good_bucket_name(self, name, prefix=None):
        """
        Attempt to create a bucket with a specified name and (specified or
        default) prefix, returning the results of that effort.
        """
        # tests using this with the default prefix must *not* rely on
        # being able to set the initial character, or exceed the max len.
        # tests using this with a custom prefix are responsible for doing
        # their own setup/teardown nukes, with their custom prefix; this
        # should be very rare.
        if prefix is None:
            prefix = bucketname.get_unique_bucket_name_prefix()
        self._create_bucket('{prefix}{name}'.format(prefix=prefix, name=name,))

    # port from function: _test_bucket_create_naming_good_long() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def check_good_long_bucket_name(self, length):
        """
        Attempt to create a bucket whose name (including the prefix) is of a
        specified length.
        """
        prefix = bucketname.get_unique_bucket_name_prefix()
        assert len(prefix) < 255
        num = length - len(prefix)
        self._create_bucket(
            '{prefix}{name}'.format(prefix=prefix, name=num*'a',))

    @triage
    # fakes3 issue: S3ResponseError isn't raised and the bucket has be created
    # ecs issue is the same as fakes3 issue
    @not_supported('fakes3', 'ecs')
    # port from test cases:
    #   test_bucket_create_naming_bad_short_empty(),
    #   test_bucket_create_naming_bad_short_one() and
    #   test_bucket_create_naming_bad_short_two() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_naming_bad_short(self):
        """
        operation: create a bucket with a short name
        assertion: fails with 400 error and bucket doesn't be created
        """
        self.check_bad_bucket_name('')
        self.check_bad_bucket_name('a')
        self.check_bad_bucket_name('aa')

    @triage
    # fakes3 return: '500 Internal Server Error'
    @not_supported('fakes3')
    # port from test case: test_bucket_create_naming_bad_long() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_naming_bad_long(self):
        """
        operation: create a bucket with a long name
        assertion: fails with 400 error and bucket doesn't be created
        """
        self.check_bad_bucket_name(256*'a')
        self.check_bad_bucket_name(280*'a')
        self.check_bad_bucket_name(3000*'a')

    @triage
    # fakes3 issue: S3ResponseError isn't raised and the bucket has be created
    # awss3 issue is the same as fakes3 issue
    @not_supported('fakes3', 'awss3')
    # port from test case: test_bucket_create_naming_bad_ip() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_naming_bad_ip(self):
        """
        operation: create a bucket with a ip-like name
        assertion: fails with 400 error and bucket doesn't be created
        """
        self.check_bad_bucket_name('192.168.5.158')

    @triage
    # fakes3 issue: S3ResponseError isn't raised and the bucket has be created
    @not_supported('fakes3')
    # port from test case:
    #   test_bucket_create_naming_bad_punctuation() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_naming_bad_punctuation(self):
        """
        operation: create a bucket with the name which contains punctuation
        assertion: fails with 400 error and bucket doesn't be created
        """
        # characters other than [a-zA-Z0-9._-]
        self.check_bad_bucket_name('alpha!soup')

    @triage
    # port from test cases:
    #   test_bucket_create_naming_good_long_250(),
    #   test_bucket_create_naming_good_long_251(),
    #   test_bucket_create_naming_good_long_252(),
    #   test_bucket_create_naming_good_long_253(),
    #   test_bucket_create_naming_good_long_254() and
    #   test_bucket_create_naming_good_long_255() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_naming_good_long(self):
        """
        operation: create a bucket with specified-length name
        assertion: succeed with a new created bucket
        """
        for length in [250, 251, 252, 253, 254, 255]:
            self.check_good_long_bucket_name(length)

    @triage
    # port from test cases:
    #   test_bucket_create_naming_good_starts_alpha(),
    #   test_bucket_create_naming_good_starts_digit(),
    #   test_bucket_create_naming_good_contains_period() and
    #   test_bucket_create_naming_good_contains_hyphen() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_naming_good_chars(self):
        """
        operation: create a bucket with name which contains specified character
        assertion: the specified bucket name works
        """
        # test the bucket name which starts with alphabetic
        self.check_good_bucket_name('aaa')

        # test the bucket name which starts with numeric
        self.check_good_bucket_name('0aaa')

        # test the bucket name which contains dot
        self.check_good_bucket_name('aaa.111')

        # test the bucket name which contains hyphen
        self.check_good_bucket_name('aaa-111')

    @triage
    # port from test case:
    #   test_bucket_create_naming_bad_starts_nonalpha() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_naming_good_starts_nonalpha(self):
        """
        operation: create a bucket with a name begun with underscore
        assertion: success
        """
        bucket_name = bucketname.get_unique_bucket_name()
        self.check_good_bucket_name('_' + bucket_name, prefix='')

    @triage
    # port from test cases:
    #   test_bucket_create_naming_dns_underscore(),
    #   test_bucket_create_naming_dns_dash_at_end(),
    #   test_bucket_create_naming_dns_dot_dot(),
    #   test_bucket_create_naming_dns_dot_dash(),
    #   test_bucket_create_naming_dns_dash_dot() and
    #   test_bucket_create_naming_dns_long() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_naming_dns(self):
        """
        operation: create a bucket with the name which contains dot or dash
        assertion: succeed with a new created bucket
        """
        self.check_good_bucket_name('foo_bar')
        self.check_good_bucket_name('foo-')

        # awss3 and fakes3 are ok
        # ecs returns: 400 Bad Request, InvalidBucketName
        # self.check_good_bucket_name('foo..bar')

        self.check_good_bucket_name('foo.-bar')
        self.check_good_bucket_name('foo-.bar')

        prefix = bucketname.get_unique_bucket_name_prefix()
        assert len(prefix) < 50
        num = 100 - len(prefix)
        self.check_good_bucket_name(num * 'a')

    @triage
    # port from test case: test_bucket_list_long_name() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_list_long_name(self):
        """
        operation: create a empty bucket and list it
        assertion: the bucket's list is empty
        """
        prefix = bucketname.get_unique_bucket_name_prefix()
        length = 251
        num = length - len(prefix)
        bucket = self._create_bucket(
            '{prefix}{name}'.format(prefix=prefix, name=num*'a',))
        result = bucket.list()
        result = list(result)
        eq(result, [])

    @triage
    # ecs returns: 409 Conflict, BucketAlreadyExists
    @not_supported('ecs')
    # port from test case: test_bucket_create_exists() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_exists(self):
        """
        operation: re-create a bucket
        assertion: idempotent success
        """
        bucket = self._create_bucket()

        keyname1 = keyname.get_unique_key_name()
        keyname2 = keyname.get_unique_key_name()
        keyname3 = keyname.get_unique_key_name()

        key_names = sorted([keyname1, keyname2, keyname3])

        create_keys(bucket, keys=[keyname1, keyname2, keyname3])
        keys = bucket.get_all_keys()
        eq(key_names, [e.name for e in keys])

        # REST idempotency means this should be a nop
        bucket = self._create_bucket(bucket.name)  # ecs issue: 409 Conflict
        keys = bucket.get_all_keys()
        eq(key_names, [e.name for e in keys])

    @triage
    # ecs returns: 409 Conflict, BucketAlreadyExists
    @not_supported('ecs')
    # port from test case: test_bucket_create_exists_nonowner() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_create_exists_not_owner(self):
        """
        operation: re-create a bucket by non-owner
        assertion: idempotent success
        """
        bucket = self._create_bucket()

        keyname1 = keyname.get_unique_key_name()
        keyname2 = keyname.get_unique_key_name()
        keyname3 = keyname.get_unique_key_name()

        key_names = sorted([keyname1, keyname2, keyname3])

        create_keys(bucket, keys=[keyname1, keyname2, keyname3])
        keys = bucket.get_all_keys()
        eq(key_names, [e.name for e in keys])

        # REST idempotency means this should be a nop
        bucket = self._create_bucket(bucket.name)  # ecs issue: 409 Conflict
        keys = bucket.get_all_keys()
        eq(key_names, [e.name for e in keys])

    @triage
    # ecs returns: 409 Conflict, BucketAlreadyExists
    @not_supported('ecs')
    # port from test case: test_bucket_recreate_not_overriding() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_recreate_not_overriding(self):
        """
        operation: create bucket with objects and recreate it
        assertion: bucket recreation doesn't override keys
        """

        # create a bucket
        bucket = self._create_bucket()

        key_names = [keyname.get_unique_key_name(),
                     keyname.get_unique_key_name()]
        create_keys(bucket, keys=key_names)

        # test keys before bucket recreation
        li = bucket.list()
        names = [e.name for e in list(li)]
        eq(names, sorted(key_names))

        # recreate the existent bucket
        self._create_bucket(bucket.name)

        # test keys after bucket recreation
        li = bucket.list()
        names = [e.name for e in list(li)]
        eq(names, sorted(key_names))

    @triage
    # port from test case: test_buckets_create_then_list() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_buckets_create_then_list(self):
        """
        operation: list all buckets
        assertion: returns all expected buckets
        """
        create_buckets = [self._create_bucket() for i in range(5)]
        list_buckets = self.data_conn.get_all_buckets()
        names = frozenset(bucket.name for bucket in list_buckets)

        for bucket in create_buckets:
            if bucket.name not in names:
                raise RuntimeError("S3 implementation's GET on Service did "
                                   "not return bucket we created: "
                                   "%r", bucket.name)
