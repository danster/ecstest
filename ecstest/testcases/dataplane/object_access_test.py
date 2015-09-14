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

import socket
import ssl
import uuid

from boto.exception import S3ResponseError
from boto.s3.bucket import Bucket
from boto.s3.key import Key
from nose.plugins.attrib import attr
from nose.tools import eq_ as eq

from ecstest import bucketname
from ecstest import keyname
from ecstest import tag
from ecstest import testbase
from ecstest import utils
from ecstest.cephs3utils import assert_raises
from ecstest.cephs3utils import FakeWriteFile
from ecstest.cephs3utils import FakeReadFile
from ecstest.cephs3utils import FakeFileVerifier
from ecstest.cephs3utils import make_request
from ecstest.dec import not_supported
from ecstest.dec import triage
from ecstest.logger import logger


# port from function: _verify_atomic_key_data() of https://
#   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
def _verify_atomic_key_data(key, size=-1, char=None):
    """
    Make sure file is of the expected size and (simulated) content
    """
    fp_verify = FakeFileVerifier(char)
    key.get_contents_to_file(fp_verify)
    if size >= 0:
        eq(fp_verify.size, size)


# port from function: _simple_http_req_100_cont() of https://
#   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
def _simple_http_req_100_cont(host, port, is_secure, method, resource):
        """
        Send the specified request w/expect 100-continue
        and await confirmation.
        """
        req = '{method} {resource} HTTP/1.1\r\nHost: {host}\r\nAccept-' \
              'Encoding: identity\r\nContent-Length: 123\r\nExpect: ' \
              '100-continue\r\n\r\n'.format(method=method,
                                            resource=resource,
                                            host=host,)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if is_secure:
            s = ssl.wrap_socket(s)
        s.settimeout(5)
        s.connect((host, port))
        s.send(bytes(req, 'UTF-8'))

        try:
            data = s.recv(1024)
        except socket.error:
            print("most likely server doesn't support 100-continue")

        s.close()
        l = data.decode('utf-8').split(' ')

        assert l[0].startswith('HTTP')

        return l[1]


@attr(tags=[tag.DATA_PLANE, tag.OBJECT_IO])
class TestObjectAccess(testbase.EcsDataPlaneTestBase):
    """
    Access a object with several conditions and test the result of the response
    """

    def setUp(self):
        super(TestObjectAccess, self).setUp(create_bucket=True)
        self.bucket_list = []

    def tearDown(self):
        for bucket in self.bucket_list:
            try:
                logger.debug("delete all keys in bucket: %s", bucket.name)
                utils.delete_keys(bucket, self.target)
                self.data_conn.delete_bucket(bucket.name)
            except Exception as err:
                logger.warn("Delete bucket exception: %s", str(err))
        super(TestObjectAccess, self).tearDown()

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

    # port from function: _test_atomic_read() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def _test_atomic_read(self, file_size):
        """
        Create a file of A's, use it to set_contents_from_file.
        Create a file of B's, use it to re-set_contents_from_file.
        Re-read the contents, and confirm we get B's
        """
        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)

        # create object of <file_size> As
        fp_a = FakeWriteFile(file_size, 'A')
        key.set_contents_from_file(fp_a)

        fp_b = FakeWriteFile(file_size, 'B')
        fp_a2 = FakeReadFile(file_size, 'A',
                             lambda: key.set_contents_from_file(fp_b))

        # read object while writing it to it
        key.get_contents_to_file(fp_a2)
        fp_a2.close()

        _verify_atomic_key_data(key, file_size, 'B')

    # port from function: _test_atomic_write() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def _test_atomic_write(self, file_size):
        """
        Create a file of A's, use it to set_contents_from_file.
        Verify the contents are all A's.
        Create a file of B's, use it to re-set_contents_from_file.
        Before re-set continues, verify content's still A's
        Re-read the contents, and confirm we get B's
        """
        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)

        # create <file_size> file of A's
        fp_a = FakeWriteFile(file_size, 'A')
        key.set_contents_from_file(fp_a)

        # verify A's
        _verify_atomic_key_data(key, file_size, 'A')

        read_key = self.bucket.get_key(key_name)

        # create <file_size> file of B's
        # but try to verify the file before we finish writing all the B's
        fp_b = FakeWriteFile(file_size, 'B',
                             lambda: _verify_atomic_key_data(read_key,
                                                             file_size))
        key.set_contents_from_file(fp_b)

        # verify B's
        _verify_atomic_key_data(key, file_size, 'B')

    # port from function: _test_atomic_dual_write() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def _test_atomic_dual_write(self, file_size):
        """
        create an object, two sessions writing different contents
        confirm that it is all one or the other
        """
        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)

        # get a second key object (for the same key)
        # so both can be writing without interfering
        key2 = self.bucket.new_key(key_name)

        # write <file_size> file of B's
        # but before we're done, try to write all A's
        fp_a = FakeWriteFile(file_size, 'A')
        fp_b = FakeWriteFile(file_size, 'B',
                             lambda: key2.set_contents_from_file(fp_a,
                                                                 rewind=True))
        key.set_contents_from_file(fp_b)
        # verify the file
        _verify_atomic_key_data(key, file_size)

    # port from function: _test_atomic_conditional_write() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def _test_atomic_conditional_write(self, file_size):
        """
        Create a file of A's, use it to set_contents_from_file.
        Verify the contents are all A's.
        Create a file of B's, use it to re-set_contents_from_file.
        Before re-set continues, verify content's still A's
        Re-read the contents, and confirm we get B's
        """
        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)

        # create <file_size> file of A's
        fp_a = FakeWriteFile(file_size, 'A')
        key.set_contents_from_file(fp_a)

        # verify A's
        _verify_atomic_key_data(key, file_size, 'A')

        read_key = self.bucket.get_key(key_name)

        # create <file_size> file of B's
        # but try to verify the file before we finish writing all the B's
        fp_b = FakeWriteFile(file_size, 'B',
                             lambda: _verify_atomic_key_data(read_key,
                                                             file_size))

        key.set_contents_from_file(fp_b, headers={'If-Match': '*'})
        # verify the file
        _verify_atomic_key_data(key, file_size, 'B')

    # port from function: _test_atomic_dual_conditional_write() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def _test_atomic_dual_conditional_write(self, file_size):
        """
        create an object, two sessions writing different contents
        confirm that it is all one or the other
        """
        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)

        fp_a = FakeWriteFile(file_size, 'A')
        key.set_contents_from_file(fp_a)
        _verify_atomic_key_data(key, file_size, 'A')
        etag_fp_a = key.etag.replace('"', '').strip()

        # get a second key object (for the same key)
        # so both can be writing without interfering
        key2 = self.bucket.new_key(key_name)

        # write <file_size> file of C's
        # but before we're done, try to write all B's
        fp_b = FakeWriteFile(file_size, 'B')
        func = lambda: \
            key2.set_contents_from_file(fp_b, rewind=True,
                                        headers={'If-Match': etag_fp_a})
        fp_c = FakeWriteFile(file_size, 'C', func)

        key.set_contents_from_file(fp_c, headers={'If-Match': etag_fp_a})
        # verify the file
        _verify_atomic_key_data(key, file_size, 'C')

    def _set_get_metadata(self, metadata, metaname=None):
        """
        create a new key in a (new or specified) bucket,
        set the meta1 property to a specified, value,
        and then re-read and return that property
        """
        if metaname is None:
            metaname = 'meta1'

        key = Key(self.bucket)
        key.key = 'key_name_test_for_meta'
        key.set_metadata(metaname, metadata)
        key.set_contents_from_string('key_contents_test_for_meta')

        key2 = self.bucket.get_key('key_name_test_for_meta')
        return key2.get_metadata(metaname)

    @triage
    # port from test case: test_ranged_request_response_code() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_ranged_request_response_code(self):
        """
        operation: fetch range of key by specified start point and end point
        assertion: return correct data with 206 status code
        """

        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        key.open('r', headers={'Range': 'bytes=4-7'})
        status = key.resp.status
        fetched_content = b''
        for data in key:
            fetched_content += data
        key.close()

        eq(fetched_content.decode('utf-8'), key_name[4:8])
        eq(status, 206)

    @triage
    # port from test case:
    #   test_ranged_request_skip_leading_bytes_response_code() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_ranged_request_skip_leading_bytes_response_code(self):
        """
        operation: fetch range of key by specified start point
        assertion: return correct data with 206 status code
        """
        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        # test trailing bytes
        key.open('r', headers={'Range': 'bytes=4-'})
        status = key.resp.status
        fetched_content = b''
        for data in key:
            fetched_content += data
        key.close()

        eq(fetched_content.decode('utf-8'), key_name[4:])
        eq(status, 206)

    @triage
    # fakes3 returns first specified bytes from start point of key
    @not_supported('fakes3')
    # port from test case:
    #   test_ranged_request_return_trailing_bytes_response_code() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_ranged_request_return_trailing_bytes_response_code(self):
        """
        operation: fetch range of key by specified negative bytes
        assertion: return correct data with 206 status code
        """
        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        # test leading bytes
        key.open('r', headers={'Range': 'bytes=-7'})
        status = key.resp.status
        fetched_content = b''
        for data in key:
            fetched_content += data
        key.close()

        eq(fetched_content.decode('utf-8'), key_name[-7:])
        # fakes3 returns first 8 bytes
        eq(status, 206)

    @triage
    @not_supported('fakes3')
    # port from test cases:
    #   test_atomic_read_1mb(),
    #   test_atomic_read_4mb() and
    #   test_atomic_read_8mb() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_atomic_read(self):
        """
        operation: read data with specified length atomicity
        assertion: the data matches what we expect
        """
        # awss3 and fakes3 are ok, ecs returns
        self._test_atomic_read(1024*1024)

        # awss3 is ok, fakes3 returns wrong content of key, ecs returns
        # self._test_atomic_read(1024*1024*4)

        # awss3 is ok, fakes3 doesn't return 1024*1024*8
        self._test_atomic_read(1024*1024*8)

    @triage
    # port from test cases:
    #   test_atomic_write_1mb(),
    #   test_atomic_write_4mb() and
    #   test_atomic_write_8mb() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_atomic_write(self):
        """
        operation: write data with specified length atomicity
        assertion: the data matches what we expect
        """
        # ecs returns
        self._test_atomic_write(1024*1024)

        # ecs returns
        self._test_atomic_write(1024*1024*4)

        # ecs returns
        self._test_atomic_write(1024*1024*8)

    @triage
    # port from test cases:
    #   test_atomic_dual_write_1mb(),
    #   test_atomic_dual_write_4mb() and
    #   test_atomic_dual_write_8mb() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_atomic_dual_write(self):
        """
        operation: write data to object dually
        assertion: the data matches what we expect
        """
        # ecs returns
        self._test_atomic_dual_write(1024*1024)

        # ecs returns
        self._test_atomic_dual_write(1024*1024*4)

        # ecs returns
        self._test_atomic_dual_write(1024*1024*8)

    @triage
    # awss3 issue: BrokenPipeError is raised when set_contents_from_file
    @not_supported('awss3')
    # port from test case: test_atomic_conditional_write_1mb() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_atomic_conditional_write(self):
        """
        operation: write data to object conditionally
        assertion: the data matches what we expect
        """
        self._test_atomic_conditional_write(1024*1024)

    @triage
    # awss3 issue: BrokenPipeError is raised when set_contents_from_file
    @not_supported('awss3')
    # port from test case: test_atomic_dual_conditional_write_1mb() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_atomic_dual_conditional_write(self):
        """
        operation: write data to object dually and conditionally
        assertion: the data matches what we expect
        """
        self._test_atomic_dual_conditional_write(1024*1024)

    @triage
    # awss3 issue: BrokenPipeError is raised when set_contents_from_file
    @not_supported('awss3')
    # port from test case: test_atomic_write_bucket_gone() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_atomic_write_bucket_gone(self):
        """
        operation: write file in deleted bucket
        assertion: the data matches what we expect
        """
        bucket = self._create_bucket()

        def remove_bucket():
            bucket.delete()

        # create file of A's but delete the bucket it's in before we
        # finish writing all of them
        key_name = keyname.get_unique_key_name()
        key = bucket.new_key(key_name)
        fp_a = FakeWriteFile(1024*1024, 'A', remove_bucket)

        key.set_contents_from_file(fp_a)
        # verify the file
        _verify_atomic_key_data(key, 1024*1024, 'A')

    @triage
    # port from test case: test_object_read_notexist() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_read_notexist(self):
        """
        operation: read contents that were never written
        assertion: fail with 404 error
        """
        bucket = self._create_bucket()
        key_name = keyname.get_unique_key_name()
        key = bucket.new_key(key_name)

        e = assert_raises(S3ResponseError, key.get_contents_as_string)
        eq(e.status, 404)
        eq(e.reason, 'Not Found')
        eq(e.error_code, 'NoSuchKey')

    @triage
    # port from test cases:
    #   test_object_create_special_characters() and
    #   test_object_create_unreadable() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_create_special_characters(self):
        """
        operation: create objects with special characters and write contents
        assertion: success
        """
        bucket = self._create_bucket()

        for name in ['<&>"\'', '\x0a']:
            key = bucket.new_key(name)
            contents = str(uuid.uuid4())
            key.set_contents_from_string(contents)
            got = key.get_contents_as_string()
            eq(got.decode('utf-8'), contents)

        bucket.get_all_keys()

    @triage
    # fakes3 issue: S3ResponseError(400 Bad Request) is raised
    #   when bucket.delete_keys(stored_keys)
    @not_supported('fakes3')
    # port from test case: test_multi_object_delete() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_multi_object_delete(self):
        """
        operation: delete multiple objects from bucket with a single call
        assertion: the results of calls match are correct
        """
        bucket = self._create_bucket()

        key_name1 = keyname.get_unique_key_name()
        key_name2 = keyname.get_unique_key_name()
        key1 = bucket.new_key(key_name1)
        key1.set_contents_from_string(key_name1)
        key2 = bucket.new_key(key_name2)
        key2.set_contents_from_string(key_name2)

        stored_keys = bucket.get_all_keys()
        eq(len(stored_keys), 2)
        # S3ResponseError(400 Bad Request) is raised by fakes3
        result = bucket.delete_keys(stored_keys)

        eq(len(result.deleted), 2)
        eq(len(result.errors), 0)
        eq(len(bucket.get_all_keys()), 0)

        # now remove again, should all succeed due to idempotency
        result = bucket.delete_keys(stored_keys)
        eq(len(result.deleted), 2)
        eq(len(result.errors), 0)
        eq(len(bucket.get_all_keys()), 0)

    @triage
    # port from test case: test_object_write_check_etag() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_write_check_etag(self):
        """
        operation: write key and read the etag from response header
        assertion: etag is correct
        """
        bucket = self._create_bucket()
        key = bucket.new_key('bar')

        res = make_request(self.data_conn, 'PUT', bucket, key, body='bar',
                           authenticated=True)
        eq(res.status, 200)
        eq(res.reason, 'OK')
        eq(res.getheader("ETag"), '"37b51d194a7513e45b56f6524f2d51f2"')

    @triage
    # port from test case:
    #   test_object_write_read_update_read_delete() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_write_read_update_read_delete(self):
        """
        operation: complete object life cycle
        assertion: read back what we wrote and rewrote
        """
        bucket = self._create_bucket()

        # Write
        key_name = keyname.get_unique_key_name()
        key = bucket.new_key(key_name)
        key.set_contents_from_string(key_name)
        # Read
        got = key.get_contents_as_string()
        eq(got.decode('utf-8'), key_name)

        # Update
        key_name1 = keyname.get_unique_key_name()
        key.set_contents_from_string(key_name1)
        # Read
        got = key.get_contents_as_string()
        eq(got.decode('utf-8'), key_name1)

        # Delete
        key.delete()

    @triage
    # fakes3 metadata issue: fakes3 returns None when key.get_metadata()
    @not_supported('fakes3')
    # port from test cases:
    #   test_object_set_get_metadata_none_to_good() and
    #   test_object_set_get_metadata_none_to_empty() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_set_get_metadata_write_to_read(self):
        """
        operation: write metadata and then read it
        assertion: the metadata read matches what we wrote
        """
        got = self._set_get_metadata(metaname='meta1', metadata='mymeta')
        eq(got, 'mymeta')

        got = self._set_get_metadata(metaname='meta2', metadata='')
        eq(got, '')

    @triage
    @not_supported('fakes3')  # fakes3 metadata issue
    # port from test cases:
    #   test_object_set_get_metadata_overwrite_to_good() and
    #   test_object_set_get_metadata_overwrite_to_empty() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_set_get_metadata_overwrite(self):
        """
        operation: write metadata and then overwrite it
        assertion: the metadata read matches what we overwrote
        """
        got = self._set_get_metadata(metaname='meta1', metadata='oldmeta1')
        eq(got, 'oldmeta1')
        got = self._set_get_metadata(metaname='meta1', metadata='newmeta1')
        eq(got, 'newmeta1')

        got = self._set_get_metadata(metaname='meta2', metadata='oldmeta2')
        eq(got, 'oldmeta2')
        got = self._set_get_metadata(metaname='meta2', metadata='')
        eq(got, '')

    @triage
    @not_supported('fakes3')  # fakes3 metadata issue
    # port from test cases:
    #   test_object_set_get_unicode_metadata() and
    #   test_object_set_get_non_utf8_metadata() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_set_get_metadata_unicode(self):
        """
        operation: write unicode metadata or non-unicode metadata
        assertion: the metadata read matches what we overwrote
        """
        got = self._set_get_metadata(metaname='meta1', metadata=u'data\xe9')
        eq(got, u'data\xe9')

        got = self._set_get_metadata(metaname='meta2', metadata='\x04data')
        eq(got, '\x04data')

    @triage
    # port from test case:
    #   test_object_metadata_replaced_on_put() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_metadata_replaced_on_put(self):
        """
        operation: write metadata and then overwriting contents to object
        assertion: return no metadata after overwriting contents to object
        """
        # create object with metadata
        key = self.bucket.new_key('foo')
        key.set_metadata('meta1', 'bar')
        key.set_contents_from_string('bar')

        # overwrite previous object, no metadata
        key2 = self.bucket.new_key('foo')
        key2.set_contents_from_string('bar')

        # should see no metadata after overwriting contents to object
        key3 = self.bucket.get_key('foo')
        got = key3.get_metadata('meta1')
        eq(got, None)

    @triage
    # fakes3 returns 100 but 403 when requests.post()
    @not_supported('ecs', 'fakes3')  # ecs 400 issue
    # port from test case: test_100_continue() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_100_continue(self):
        """
        operation: expect continue
        assertion: succeeds if object is public-read-write
        """

        bucket = self.bucket
        objname = keyname.get_unique_key_name()

        res = '/{bucket}/{obj}'.format(bucket=bucket.name, obj=objname)

        is_secure = self.cfg['ACCESS_SSL']
        port = self.cfg['ACCESS_PORT']
        host = self.cfg['ACCESS_SERVER']

        # ecs returns 400, fakes3 returns 100
        status = _simple_http_req_100_cont(host, port, is_secure, 'PUT', res)
        eq(status, '403')

        bucket.set_acl('public-read-write')

        status = _simple_http_req_100_cont(host, port, is_secure, 'PUT', res)
        eq(status, '100')
