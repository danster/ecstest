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

from boto.s3.bucket import Bucket
from boto.s3.key import Key
from nose.plugins.attrib import attr
from nose.tools import eq_ as eq

from ecstest import bucketname
from ecstest import keyname
from ecstest import tag
from ecstest import testbase
from ecstest import utils
from ecstest.dec import not_supported
from ecstest.dec import triage
from ecstest.logger import logger


def _get_keys_prefixes(li):
    """
    figure out which of the strings in a list are actually keys
    return lists of strings that are (keys) and are not (prefixes)
    """
    keys = [x for x in li if isinstance(x, Key)]
    prefixes = [x for x in li if not isinstance(x, Key)]
    return (keys, prefixes)


@attr(tags=[tag.DATA_PLANE, tag.OBJECT_LIST])
class TestObjectList(testbase.EcsDataPlaneTestBase):
    """
    Post several objects and list them within a bucket
    """
    def setUp(self):
        super(TestObjectList, self).setUp(create_bucket=True)

    def tearDown(self):
        super(TestObjectList, self).tearDown()

    def _create_bucket(self, bucket_name=None):
        """
        To create bucket with bucket_name
        """
        if bucket_name is None:
            bucket_name = bucketname.get_unique_bucket_name()

        logger.debug("Create bucket: %s", bucket_name)
        bucket = self.data_conn.create_bucket(bucket_name)
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

    @triage
    # port from test case: test_bucket_list_distinct() of https://github.com/
    #   ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_list_from_distinct_bucket(self):
        """
        operation: list
        assertion: distinct buckets have different contents
        """
        bucket1 = self._create_bucket()
        bucket2 = self._create_bucket()

        name = keyname.get_unique_key_name()
        key = bucket1.new_key(name)
        key.set_contents_from_string(name)

        l = bucket2.list()
        l = list(l)
        eq(l, [])

        for bucket in [bucket1, bucket2]:
            logger.debug("delete all keys in bucket: %s", bucket.name)
            utils.delete_keys(bucket, self.target)
            self.data_conn.delete_bucket(bucket.name)

    @triage
    # ecs marker issue: the response Keys contain the marker ,
    #   that is not consistent with aws-s3 which don't contain the marker.
    # fakes3 MaxKeys issue: the response MaxKeys always be 1000
    #   no matter what the request max_keys are.
    @not_supported('fakes3', 'ecs')  # fakes3 MaxKeys issue, ecs marker issue
    # port from test case: test_bucket_list_many() of https://github.com/
    #   ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_list_many(self):
        """
        operation: list
        assertion: pagination w/max_keys=2, no marker
        """
        keyname1 = keyname.get_unique_key_name()
        keyname2 = keyname.get_unique_key_name()
        keyname3 = keyname.get_unique_key_name()

        keynames = [keyname1, keyname2, keyname3]
        self._create_keys(keys=keynames)

        # bucket.list() is high-level and will not let us set max-keys,
        # using it would require using >1000 keys to test, and that would
        # be too slow; use the lower-level call bucket.get_all_keys()
        # instead

        l = self.bucket.get_all_keys(max_keys=2)
        eq(len(l), 2)
        eq(l.is_truncated, True)
        names = [e.name for e in l]

        keynames = sorted(keynames)
        eq(names, keynames[:2])

        l = self.bucket.get_all_keys(max_keys=2, marker=names[-1])
        eq(len(l), 1)
        eq(l.is_truncated, False)
        names = [e.name for e in l]
        eq(names, keynames[2:])

    @triage
    # port from test case: test_bucket_list_delimiter_basic() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_list_delimiter_basic(self):
        """
        operation: list under delimiter
        assertion: prefixes in multi-component object names
        """
        self._create_keys(
            keys=['foo/bar', 'foo/baz/xyzzy', 'quux/thud', 'asdf'])

        # listings should treat / delimiter in a directory-like fashion
        li = self.bucket.list(delimiter='/')
        eq(li.delimiter, '/')

        # asdf is the only terminal object that should appear in the listing
        (keys, prefixes) = _get_keys_prefixes(li)
        names = [e.name for e in keys]
        eq(names, ['asdf'])

        # In Amazon, you will have two CommonPrefixes elements, each with a
        # single prefix. According to Amazon documentation (http://docs.aws.
        # amazon.com/AmazonS3/latest/API/RESTBucketGET.html), the response's
        # CommonPrefixes should contain all the prefixes, which DHO does.
        #
        # Unfortunately, boto considers a CommonPrefixes element as a prefix,
        # and will store the last Prefix element within a CommonPrefixes
        # element, effectively overwriting any other prefixes.

        # the other returned values should be the pure prefixes foo/ and quux/
        prefix_names = [e.name for e in prefixes]
        eq(len(prefixes), 2)
        eq(prefix_names, ['foo/', 'quux/'])

    @triage
    # port from test case: test_bucket_list_delimiter_alt() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_list_delimiter_alt(self):
        """
        operation: list under delimiter
        assertion: non-slash delimiter characters
        """
        self._create_keys(keys=['bar', 'baz', 'cab', 'foo'])

        li = self.bucket.list(delimiter='a')
        eq(li.delimiter, 'a')

        # foo contains no 'a' and so is a complete key
        (keys, prefixes) = _get_keys_prefixes(li)
        names = [e.name for e in keys]
        eq(names, ['foo'])

        # bar, baz, and cab should be broken up by the 'a' delimiters
        prefix_names = [e.name for e in prefixes]
        eq(len(prefixes), 2)
        eq(prefix_names, ['ba', 'ca'])

    @triage
    # port from test cases:
    #   test_bucket_list_delimiter_unreadable(),
    #   test_bucket_list_delimiter_empty() and
    #   test_bucket_list_delimiter_not_exist() of https://github.com/ceph/
    #   s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_list_delimiter_invalid(self):
        """
        operation: list under delimiter
        assertion: non-printable, empty, unused delimiter can be specified
        """
        keyname1 = keyname.get_unique_key_name()
        keyname2 = keyname.get_unique_key_name()
        keyname3 = keyname.get_unique_key_name()
        keyname4 = keyname.get_unique_key_name()

        keynames = [keyname1, keyname2, keyname3, keyname4]
        self._create_keys(keys=keynames)

        keynames = sorted(keynames)

        for _delimiter in ['\x0a', '', '/']:
            li = self.bucket.list(delimiter=_delimiter)
            eq(li.delimiter, _delimiter)

            (keys, prefixes) = _get_keys_prefixes(li)
            names = [e.name for e in keys]
            eq(names, keynames)
            eq(prefixes, [])
