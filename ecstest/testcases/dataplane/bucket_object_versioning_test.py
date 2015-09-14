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

import itertools
import time
import threading

from boto.s3.bucket import Bucket
from boto.s3.deletemarker import DeleteMarker
from nose.plugins.attrib import attr
from nose.tools import eq_ as eq

from ecstest import bucketname
from ecstest import keyname
from ecstest import tag
from ecstest import testbase
from ecstest import utils
from ecstest.cephs3utils import check_grants
from ecstest.cephs3utils import do_test_multipart_upload_contents
from ecstest.dec import not_supported
from ecstest.dec import triage
from ecstest.logger import logger


def check_versioning(bucket, status):
    try:
        eq(bucket.get_versioning_status()['Versioning'], status)
    except KeyError:
        eq(None, status)


# amazon is eventual consistent, retry a bit if failed
def check_configure_versioning_retry(bucket, status, expected_string):
    read_status = None
    bucket.configure_versioning(status)

    for i in range(10):
        try:
            read_status = bucket.get_versioning_status()['Versioning']
        except KeyError:
            read_status = None

        if expected_string is read_status:
            break
        time.sleep(2)

    eq(read_status, expected_string)


def check_head_obj_content(key, content):
    if content is not None:
        eq(key.get_contents_as_string().decode('utf-8'), content)
    else:
        eq(key, None)


def check_obj_content(key, content):
    if content is not None:
        eq(key.get_contents_as_string().decode('utf-8'), content)
    else:
        eq(isinstance(key, DeleteMarker), True)


def check_obj_versions(bucket, objname, keys, contents):
    # check to see if object is pointing at correct version
    key = bucket.get_key(objname)

    if len(contents) > 0:
        print('testing obj head', objname)
        check_head_obj_content(key, contents[-1])
        i = len(contents)
        for key in bucket.list_versions():
            if key.name != objname:
                continue

            i -= 1
            eq(keys[i].version_id or 'null', key.version_id)
            print('testing obj version-id=', key.version_id)
            check_obj_content(key, contents[i])
    else:
        eq(key, None)


def create_multiple_versions(bucket, objname, num_versions, k=None, c=None):
    c = c or []
    k = k or []
    for i in range(num_versions):
        c.append('content-{i}'.format(i=i))

        key = bucket.new_key(objname)
        key.set_contents_from_string(c[i])

        if i == 0:
            check_configure_versioning_retry(bucket, True, "Enabled")

    k_pos = len(k)
    i = 0
    for o in bucket.list_versions():
        if o.name != objname:
            continue
        i += 1
        if i > num_versions:
            break

        k.insert(k_pos, o)

    eq(len(k), len(c))
    check_obj_versions(bucket, objname, k, c)
    return k, c


def remove_obj_version(bucket, k, c, i):
    # check by versioned key
    i = i % len(k)
    rmkey = k.pop(i)
    content = c.pop(i)
    if (not rmkey.delete_marker):
        eq(rmkey.get_contents_as_string().decode('utf-8'), content)

    # remove version
    print('removing version_id=', rmkey.version_id)
    bucket.delete_key(rmkey.name, version_id=rmkey.version_id)
    check_obj_versions(bucket, rmkey.name, k, c)


def remove_obj_head(bucket, objname, k, c):
    print('removing obj=', objname)
    key = bucket.delete_key(objname)

    k.append(key)
    c.append(None)

    eq(key.delete_marker, True)
    check_obj_versions(bucket, objname, k, c)


def _do_test_create_remove_versions(bucket, objname, num_versions,
                                    remove_start_idx, idx_inc):

    (k, c) = create_multiple_versions(bucket, objname, num_versions)
    idx = remove_start_idx

    for j in range(num_versions):
        remove_obj_version(bucket, k, c, idx)
        idx += idx_inc


def _do_remove_versions(bucket, objname, remove_start_idx,
                        idx_inc, head_rm_ratio, k, c):

    idx = remove_start_idx
    r = 0
    total = len(k)

    for j in range(total):
        r += head_rm_ratio
        if r >= 1:
            r %= 1
            remove_obj_head(bucket, objname, k, c)
        else:
            remove_obj_version(bucket, k, c, idx)
            idx += idx_inc

    check_obj_versions(bucket, objname, k, c)


def _do_test_create_remove_versions_and_head(bucket, objname, num_versions,
                                             num_ops, remove_start_idx,
                                             idx_inc, head_rm_ratio):

    (k, c) = create_multiple_versions(bucket, objname, num_versions)
    _do_remove_versions(bucket, objname, remove_start_idx,
                        idx_inc, head_rm_ratio, k, c)


def is_null_key(k):
    return (k.version_id is None) or (k.version_id == 'null')


def delete_suspended_versioning_obj(bucket, objname, k, c):
    key = bucket.delete_key(objname)

    i = 0
    while i < len(k):
        if is_null_key(k[i]):
            k.pop(i)
            c.pop(i)
        else:
            i += 1

    key.version_id = "null"
    k.append(key)
    c.append(None)

    check_obj_versions(bucket, objname, k, c)


def overwrite_suspended_versioning_obj(bucket, objname, k, c, content):
    key = bucket.new_key(objname)
    key.set_contents_from_string(content)

    i = 0
    while i < len(k):
        if is_null_key(k[i]):
            k.pop(i)
            c.pop(i)
        else:
            i += 1

    k.append(key)
    c.append(content)

    check_obj_versions(bucket, objname, k, c)


def _count_bucket_versioned_objs(bucket):
    k = []
    for key in bucket.list_versions():
        k.insert(0, key)
    return len(k)


def _do_create_object(bucket, objname, i):
    k = bucket.new_key(objname)
    k.set_contents_from_string('data {i}'.format(i=i))


def _do_remove_ver(bucket, obj):
    bucket.delete_key(obj.name, version_id=obj.version_id)


def _do_create_versioned_obj_concurrent(bucket, objname, num):
    t = []
    for i in range(num):
        thr = threading.Thread(target=_do_create_object,
                               args=(bucket, objname, i))
        thr.start()
        t.append(thr)
    return t


def _do_clear_versioned_bucket_concurrent(bucket):
    t = []
    for o in bucket.list_versions():
        thr = threading.Thread(target=_do_remove_ver, args=(bucket, o))
        thr.start()
        t.append(thr)
    return t


def _do_wait_completion(t):
    for thr in t:
        thr.join()


@attr(tags=[tag.DATA_PLANE, tag.BUCKET_MGMT])
class TestBucketObjectVersioning(testbase.EcsDataPlaneTestBase):
    """
    Change and check the versioning status of buckets or objects
    """

    def setUp(self):
        super(TestBucketObjectVersioning, self).setUp()
        self.bucket_list = []

    def tearDown(self):
        for bucket in self.bucket_list:
            try:
                for k in bucket.list_versions():
                    bucket.delete_key(k.name, version_id=k.version_id)

                utils.delete_keys(bucket, self.target)
                self.data_conn.delete_bucket(bucket.name)
            except Exception as err:
                logger.warn("Delete bucket exception: %s", str(err))
        super(TestBucketObjectVersioning, self).tearDown()

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
    # fakes3 versioning issue: the buckets of fakes3 don't support versioning
    #   through bucket.configure_versioning(True or False) and fakes3 can't get
    #   versioning status through bucket.get_versioning_status()
    # ecs versioning issue: ecs returns 500 Server Error(InternalError) through
    #   bucket.configure_versioning(True or False)
    @not_supported('fakes3', 'ecs')
    # port from test case: test_versioning_bucket_create_suspend() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_bucket_create_suspend(self):
        """
        operation: create and remove versioned bucket
        assertion: the versioning status of bucket matches what we expect
        """

        bucket = self._create_bucket()
        check_versioning(bucket, None)

        check_configure_versioning_retry(bucket, False, "Suspended")
        check_configure_versioning_retry(bucket, True, "Enabled")
        check_configure_versioning_retry(bucket, True, "Enabled")
        check_configure_versioning_retry(bucket, False, "Suspended")

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case: test_versioning_obj_create_read_remove() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_obj_create_read_remove(self):
        """
        operation: create and remove versioned object
        assertion: the versioning status of object matches what we expect
        """
        bucket = self._create_bucket()

        objname = keyname.get_unique_key_name()
        num_versions = 5

        _do_test_create_remove_versions(bucket, objname, num_versions, -1, 0)
        _do_test_create_remove_versions(bucket, objname, num_versions, -1, 0)
        _do_test_create_remove_versions(bucket, objname, num_versions, 0, 0)
        _do_test_create_remove_versions(bucket, objname, num_versions, 1, 0)
        _do_test_create_remove_versions(bucket, objname, num_versions, 4, -1)
        _do_test_create_remove_versions(bucket, objname, num_versions, 3, 3)

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case:
    #   test_versioning_obj_create_read_remove_head() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_obj_create_read_remove_head(self):
        """
        operation: create and remove versioned object and head
        assertion: the versioning status of object matches what we expect
        """
        bucket = self._create_bucket()
        objname = keyname.get_unique_key_name()
        num_versions = 5

        _do_test_create_remove_versions_and_head(bucket, objname, num_versions,
                                                 num_versions * 2, -1, 0, 0.5)

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test cases:
    #   test_versioning_obj_suspend_versions() and
    #   test_versioning_obj_suspend_versions_simple() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_obj_suspend_versions(self):
        """
        operation: suspend versioned bucket
        assertion: suspended versioning behaves correctly
        """

        bucket = self._create_bucket()
        check_versioning(bucket, None)

        check_configure_versioning_retry(bucket, True, "Enabled")

        num_versions = 5
        objname = keyname.get_unique_key_name()

        (k, c) = create_multiple_versions(bucket, objname, num_versions)
        check_configure_versioning_retry(bucket, False, "Suspended")

        delete_suspended_versioning_obj(bucket, objname, k, c)
        delete_suspended_versioning_obj(bucket, objname, k, c)
        overwrite_suspended_versioning_obj(bucket, objname, k, c,
                                           'null content 1')
        overwrite_suspended_versioning_obj(bucket, objname, k, c,
                                           'null content 2')

        delete_suspended_versioning_obj(bucket, objname, k, c)
        overwrite_suspended_versioning_obj(bucket, objname, k, c,
                                           'null content 3')

        delete_suspended_versioning_obj(bucket, objname, k, c)
        check_configure_versioning_retry(bucket, True, "Enabled")

        (k, c) = create_multiple_versions(bucket, objname, 3, k, c)
        _do_remove_versions(bucket, objname, 0, 5, 0.5, k, c)
        _do_remove_versions(bucket, objname, 0, 5, 0, k, c)

        eq(len(k), 0)
        eq(len(k), len(c))

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case:
    #   test_versioning_obj_create_versions_remove_all() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_obj_create_versions_remove_all(self):
        """
        operation: create and remove versions
        assertion: everything works
        """

        bucket = self._create_bucket()
        check_versioning(bucket, None)

        check_configure_versioning_retry(bucket, True, "Enabled")

        num_versions = 10
        objname = keyname.get_unique_key_name()

        (k, c) = create_multiple_versions(bucket, objname, num_versions)

        _do_remove_versions(bucket, objname, 0, 5, 0.5, k, c)
        _do_remove_versions(bucket, objname, 0, 5, 0, k, c)

        eq(len(k), 0)
        eq(len(k), len(c))

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case:
    #   test_versioning_obj_create_overwrite_multipart() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_obj_create_overwrite_multipart(self):
        """
        operation: create and test multipart object
        assertion: everything works
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")

        objname = keyname.get_unique_key_name()
        c = []
        num_versions = 3

        for i in range(num_versions):
            c.append(do_test_multipart_upload_contents(bucket, objname, 3))

        k = []
        for key in bucket.list_versions():
            k.insert(0, key)

        eq(len(k), num_versions)
        check_obj_versions(bucket, objname, k, c)

        _do_remove_versions(bucket, objname, 0, 3, 0.5, k, c)
        _do_remove_versions(bucket, objname, 0, 3, 0, k, c)

        eq(len(k), 0)
        eq(len(k), len(c))

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case: test_versioning_obj_list_marker() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_obj_list_marker(self):
        """
        operation: list versioned objects
        assertion: everything works
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")

        objname = keyname.get_unique_key_name()
        objname2 = keyname.get_unique_key_name()

        num_versions = 5

        (k, c) = create_multiple_versions(bucket, objname, num_versions)
        time.sleep(3)
        (k2, c2) = create_multiple_versions(bucket, objname2, num_versions)

        k.reverse()
        k2.reverse()
        allkeys = k + k2
        names = []

        for key1, key2 in itertools.zip_longest(bucket.list_versions(),
                                                allkeys):
            print(key1.version_id, key2.version_id)
            eq(key1.version_id, key2.version_id)
            names.append(key1.name)

        for i in range(len(allkeys)):
            for key1, key2 in itertools.zip_longest(bucket.list_versions(
                    key_marker=names[i],
                    version_id_marker=allkeys[i].version_id),
                    allkeys[i+1:]):
                eq(key1.version_id, key2.version_id)

        # with nonexisting version id, skip to next object
        for key1, key2 in itertools.zip_longest(bucket.list_versions(
                key_marker=objname), allkeys[5:]):

                eq(key1.version_id, key2.version_id)

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case: test_versioning_copy_obj_version() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_copy_obj_version(self):
        """
        operation: create and test versioned object copying
        assertion: everything works
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")

        num_versions = 3
        objname = keyname.get_unique_key_name()

        (k, c) = create_multiple_versions(bucket, objname, num_versions)

        # copy into the same bucket
        for i in range(num_versions):
            new_key_name = 'key_{i}'.format(i=i)
            new_key = bucket.copy_key(new_key_name, bucket.name, k[i].name,
                                      src_version_id=k[i].version_id)
            eq(new_key.get_contents_as_string().decode('utf-8'), c[i])

        bucket_2 = self._create_bucket()

        # copy into a different bucket
        for i in range(num_versions):
            new_key_name = 'key_{i}'.format(i=i)
            new_key = bucket_2.copy_key(new_key_name, bucket.name, k[i].name,
                                        src_version_id=k[i].version_id)
            eq(new_key.get_contents_as_string().decode('utf-8'), c[i])

        # test copy of head object
        new_key = bucket_2.copy_key('new_key', bucket.name, objname)
        eq(new_key.get_contents_as_string().decode('utf-8'),
           c[num_versions - 1])

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case: test_versioning_multi_object_delete() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_multi_object_delete(self):
        """
        operation: delete multiple versions
        assertion: deletes multiple versions of an object with a single call
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")
        key_name = keyname.get_unique_key_name()

        key0 = bucket.new_key(key_name)
        key0.set_contents_from_string('foo')
        key1 = bucket.new_key(key_name)
        key1.set_contents_from_string('bar')

        stored_keys = []
        for key in bucket.list_versions():
            stored_keys.insert(0, key)

        eq(len(stored_keys), 2)

        result = bucket.delete_keys(stored_keys)
        eq(len(result.deleted), 2)
        eq(len(result.errors), 0)

        eq(_count_bucket_versioned_objs(bucket), 0)

        # now remove again, should all succeed due to idempotency
        result = bucket.delete_keys(stored_keys)
        eq(len(result.deleted), 2)
        eq(len(result.errors), 0)

        eq(_count_bucket_versioned_objs(bucket), 0)

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case:
    #   test_versioning_multi_object_delete_with_marker() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_multi_object_delete_with_marker(self):
        """
        operation: delete multiple versions
        assertion: deletes multiple versions of an object and
                   delete marker with a single call
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")
        key_name = keyname.get_unique_key_name()

        key0 = bucket.new_key(key_name)
        key0.set_contents_from_string('foo')
        key1 = bucket.new_key(key_name)
        key1.set_contents_from_string('bar')

        key2 = bucket.delete_key(keyname)
        eq(key2.delete_marker, True)

        stored_keys = []
        for key in bucket.list_versions():
            stored_keys.insert(0, key)

        eq(len(stored_keys), 3)

        result = bucket.delete_keys(stored_keys)
        eq(len(result.deleted), 3)
        eq(len(result.errors), 0)
        eq(_count_bucket_versioned_objs(bucket), 0)

        delete_markers = []
        for o in result.deleted:
            if o.delete_marker:
                delete_markers.insert(0, o)

        eq(len(delete_markers), 1)
        eq(key2.version_id, delete_markers[0].version_id)

        # now remove again, should all succeed due to idempotency
        result = bucket.delete_keys(stored_keys)
        eq(len(result.deleted), 3)
        eq(len(result.errors), 0)

        eq(_count_bucket_versioned_objs(bucket), 0)

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case:
    #   test_versioning_multi_object_delete_with_marker_create() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioning_multi_object_delete_with_marker_create(self):
        """
        operation: multi delete create marker
        assertion: returns correct marker version id
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")
        key_name = keyname.get_unique_key_name()

        delete_keys = {bucket.new_key(key_name)}

        eq(_count_bucket_versioned_objs(bucket), 0)

        result = bucket.delete_keys(delete_keys)
        eq(len(result.deleted), 1)
        eq(_count_bucket_versioned_objs(bucket), 1)

        delete_markers = []
        for o in result.deleted:
            if o.delete_marker:
                delete_markers.insert(0, o)

        eq(len(delete_markers), 1)

        for o in bucket.list_versions():
            eq(o.name, key_name)
            eq(o.version_id, delete_markers[0].delete_marker_version_id)

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case: test_versioned_object_acl() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioned_object_acl(self):
        """
        operation: change acl on an object version changes specific version
        assertion: everything works
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")
        key_name = keyname.get_unique_key_name()

        key0 = bucket.new_key(key_name)
        key0.set_contents_from_string('bar')
        key1 = bucket.new_key(key_name)
        key1.set_contents_from_string('bla')
        key2 = bucket.new_key(key_name)
        key2.set_contents_from_string('zxc')

        stored_keys = []
        for key in bucket.list_versions():
            stored_keys.insert(0, key)

        k1 = stored_keys[1]

        policy = bucket.get_acl(key_name=k1.name, version_id=k1.version_id)

        default_policy = [
            dict(
                permission='FULL_CONTROL',
                id=policy.owner.id,
                display_name=policy.owner.display_name,
                uri=None,
                email_address=None,
                type='CanonicalUser',
                ),
            ]

        check_grants(policy.acl.grants, default_policy)

        bucket.set_canned_acl('public-read', key_name=k1.name,
                              version_id=k1.version_id)
        policy = bucket.get_acl(key_name=k1.name, version_id=k1.version_id)

        check_grants(
            policy.acl.grants,
            [
                dict(
                    permission='FULL_CONTROL',
                    id=policy.owner.id,
                    display_name=policy.owner.display_name,
                    uri=None,
                    email_address=None,
                    type='CanonicalUser',
                    ),
                dict(
                    permission='READ',
                    id=None,
                    display_name=None,
                    uri='http://acs.amazonaws.com/groups/global/AllUsers',
                    email_address=None,
                    type='Group',
                    ),
                ],
            )

        k = bucket.new_key(key_name)
        check_grants(k.get_acl().acl.grants, default_policy)

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case:
    #   test_versioned_concurrent_object_create_concurrent_remove() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioned_concurrent_object_create_concurrent_remove(self):
        """
        operation: concurrent creation of objects, concurrent removal
        assertion: everything works
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")
        key_name = keyname.get_unique_key_name()

        num_objs = 3

        for i in range(3):
            t = _do_create_versioned_obj_concurrent(bucket, key_name, num_objs)
            _do_wait_completion(t)

            eq(_count_bucket_versioned_objs(bucket), num_objs)
            eq(len(bucket.get_all_keys()), 1)

            t = _do_clear_versioned_bucket_concurrent(bucket)
            _do_wait_completion(t)

            eq(_count_bucket_versioned_objs(bucket), 0)
            eq(len(bucket.get_all_keys()), 0)

    @triage
    @not_supported('fakes3', 'ecs')  # fakes3 and ecs versioning issues
    # port from test case:
    #   test_versioned_concurrent_object_create_and_remove() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_versioned_concurrent_object_create_and_remove(self):
        """
        operation: concurrent creation and removal of objects
        assertion: everything works
        """

        bucket = self._create_bucket()
        check_configure_versioning_retry(bucket, True, "Enabled")
        key_name = keyname.get_unique_key_name()

        num_objs = 3
        all_threads = []

        for i in range(3):
            t = _do_create_versioned_obj_concurrent(bucket, key_name, num_objs)
            all_threads.append(t)

            t = _do_clear_versioned_bucket_concurrent(bucket)
            all_threads.append(t)

        for t in all_threads:
            _do_wait_completion(t)

        t = _do_clear_versioned_bucket_concurrent(bucket)
        _do_wait_completion(t)

        eq(_count_bucket_versioned_objs(bucket), 0)
        eq(len(bucket.get_all_keys()), 0)
