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

import uuid

from boto.auth_handler import AuthHandler
from boto.s3.acl import ACL
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
from ecstest.cephs3utils import check_grants
from ecstest.cephs3utils import check_access_denied
from ecstest.dec import not_supported
from ecstest.dec import triage
from ecstest.logger import logger


def _make_acl_xml(user_id, acl):
    """
    Return the xml form of an ACL entry
    """
    return '<?xml version="1.0" encoding="UTF-8"?><AccessControlPolicy ' \
           'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>' + \
           user_id + '</ID></Owner>' + acl.to_xml() + '</AccessControlPolicy>'


@attr(tags=[tag.DATA_PLANE, tag.BUCKET_MGMT])
class TestBucketACL(testbase.EcsDataPlaneTestBase):
    """
    Test the ACLs of buckets
    """

    def setUp(self):
        super(TestBucketACL, self).setUp()
        self.bucket_list = []

    def tearDown(self):
        for bucket in self.bucket_list:
            try:
                logger.debug("delete all keys in bucket: %s", bucket.name)
                utils.delete_keys(bucket, self.target)
                self.data_conn.delete_bucket(bucket.name)
            except Exception as err:
                logger.warn("Delete bucket exception: %s", str(err))
        super(TestBucketACL, self).tearDown()

    # port from function: _build_bucket_acl_xml() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def _build_bucket_acl_xml(self, permission, bucket=None):
        """
        add the specified permission for the current user to
        a (new or specified) bucket, in XML form, set it, and
        then read it back to confirm it was correctly set
        """

        # get the user id from an existed bucket
        if bucket is None:
            bucket = self._create_bucket()
        user_id = bucket.get_acl().owner.id

        acl = ACL()
        acl.add_user_grant(permission=permission, user_id=user_id)
        XML = _make_acl_xml(user_id=user_id, acl=acl)

        bucket.set_xml_acl(XML)
        policy = bucket.get_acl()
        check_grants(
            policy.acl.grants,
            [
                dict(
                    permission=permission,
                    id=policy.owner.id,
                    display_name=policy.owner.display_name,
                    uri=None,
                    email_address=None,
                    type='CanonicalUser',
                    ),
                ],
            )

    # port from function: _test_bucket_acls_changes_persistent() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def _test_bucket_acls_changes_persistent(self, bucket):
        """
        set and verify readback of each possible permission
        """
        perms = ('FULL_CONTROL', 'WRITE', 'WRITE_ACP', 'READ', 'READ_ACP')
        for p in perms:
            self._build_bucket_acl_xml(p, bucket)

    def _create_bucket(self, bucket_name=None, **params):
        """
        To create bucket with bucket_name
        """
        if bucket_name is None:
            bucket_name = bucketname.get_unique_bucket_name()

        logger.debug("Create bucket: %s", bucket_name)
        bucket = self.data_conn.create_bucket(bucket_name, **params)
        self.bucket_list.append(bucket)
        eq(isinstance(bucket, Bucket), True)

        return bucket

    @triage
    # fakes3 bucket acl issue: the policy.acl of bucket is a 'NoneType' object,
    #   and 'Policy' object has no attribute 'owner'.
    @not_supported('fakes3')
    # port from test case: test_bucket_acl_default() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_default(self):
        """
        operation: get default bucket acl after creating bucket
        assertion: grants of acl match what we want
        """
        bucket = self._create_bucket()

        policy = bucket.get_acl()
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
                ],
            )

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_canned_during_create() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_after_create_bucket(self):
        """
        operation: get bucket acl after creating it with 'public-read' policy
        assertion: grants of acl match what we want
        """
        name = bucketname.get_unique_bucket_name()
        bucket = self._create_bucket(name, policy='public-read')

        policy = bucket.get_acl()
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

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_canned() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_after_set_acl_publicread(self):
        """
        operation: get bucket acl after setting it 'public-read'
        assertion: grants of acl match what we want
        """
        bucket = self._create_bucket()

        # Since it defaults to private, set it public-read first
        bucket.set_acl('public-read')
        policy = bucket.get_acl()
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

        # Then back to private.
        bucket.set_acl('private')
        policy = bucket.get_acl()
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
                ],
            )

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_canned_publicreadwrite() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_after_set_acl_publicreadwrite(self):
        """
        operation: get bucket acl after setting it 'public-read-write'
        assertion: grants of acl match what we want
        """
        bucket = self._create_bucket()

        bucket.set_acl('public-read-write')
        policy = bucket.get_acl()
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
                dict(
                    permission='WRITE',
                    id=None,
                    display_name=None,
                    uri='http://acs.amazonaws.com/groups/global/AllUsers',
                    email_address=None,
                    type='Group',
                    ),
                ],
            )

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case:
    #   test_bucket_acl_canned_authenticatedread() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_after_set_acl_authenticatedread(self):
        """
        operation: get bucket acl after setting it 'authenticated-read'
        assertion: grants of acl match what we want
        """
        bucket = self._create_bucket()

        bucket.set_acl('authenticated-read')
        policy = bucket.get_acl()
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
                    uri='http://acs.amazonaws.com/'
                        'groups/global/AuthenticatedUsers',
                    email_address=None,
                    type='Group',
                    ),
                ],
            )

    @triage
    # port from test case:
    #   test_bucket_acl_canned_private_to_private() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_set_private_to_private(self):
        """
        operation: set a private bucket to private
        assertion: a private bucket can be set to private
        """
        bucket = self._create_bucket()
        bucket.set_acl('private')

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_xml_fullcontrol() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_xml_fullcontrol(self):
        """
        operation: set the acl of bucket to 'FULL_CONTROL' by xml format
        assertion: grants got from bucket match what we set previously
        """
        self._build_bucket_acl_xml('FULL_CONTROL')

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_xml_write() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_xml_write(self):
        """
        operation: set the acl of bucket to 'WRITE' by xml format
        assertion: grants got from bucket match what we set previously
        """
        self._build_bucket_acl_xml('WRITE')

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_xml_writeacp() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_xml_writeacp(self):
        """
        operation: set the acl of bucket to 'WRITE_ACP' by xml format
        assertion: grants got from bucket match what we set previously
        """
        self._build_bucket_acl_xml('WRITE_ACP')

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_xml_read() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_xml_read(self):
        """
        operation: set the acl of bucket to 'READ' by xml format
        assertion: grants got from bucket match what we set previously
        """
        self._build_bucket_acl_xml('READ')

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_xml_readacp() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_xml_readacp(self):
        """
        operation: set the acl of bucket to 'READ_ACP' by xml format
        assertion: grants got from bucket match what we set previously
        """
        self._build_bucket_acl_xml('READ_ACP')

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_grant_nonexist_user() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_grant_not_exist_user(self):
        """
        operation: set the acl of bucket with a bad user id
        assertion: fails with 400 error
        """

        bucket = self._create_bucket()

        # add alt user
        bad_user_id = 'user_id-' + str(uuid.uuid4())
        policy = bucket.get_acl()
        policy.acl.add_user_grant('FULL_CONTROL', bad_user_id)

        e = assert_raises(S3ResponseError, bucket.set_acl, policy)
        eq(e.status, 400)
        eq(e.reason, 'Bad Request')
        eq(e.error_code, 'InvalidArgument')

    @triage
    # ecs: the exception doesn't be raised when key.set_contents_from_string
    @not_supported('fakes3', 'ecs')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_no_grants() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_no_grants(self):
        """
        operation: revoke all ACLs of bucket
        assertion: can read obj, can get/set bucket acl, cannot write obj
        """
        bucket = self._create_bucket()

        # write content to the bucket
        key_name1 = keyname.get_unique_key_name()
        key = bucket.new_key(key_name1)
        key.set_contents_from_string(key_name1)

        # clear grants
        policy = bucket.get_acl()
        policy.acl.grants = []

        # remove read/write permission
        bucket.set_acl(policy)

        # can read
        bucket.get_key(key_name1)

        # can't write
        key_name2 = keyname.get_unique_key_name()
        key = bucket.new_key(key_name2)
        # ECS does not raise exception
        check_access_denied(key.set_contents_from_string, key_name2)

        # can get acl
        bucket.get_acl()

        # can set acl
        bucket.set_acl('private')

    @triage
    # ecs returns 'InvalidArgument' but 'UnresolvableGrantByEmailAddress'
    @not_supported('fakes3', 'ecs')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_grant_email_notexist() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_grant_not_exist_email(self):
        """
        operation: add the acl of bucket with a nonexistent user
        assertion: fails with 400 error
        """

        # behavior not documented by amazon
        bucket = self._create_bucket()

        policy = bucket.get_acl()
        policy.acl.add_email_grant('FULL_CONTROL', "__not_existed_@_email__")

        e = assert_raises(S3ResponseError, bucket.set_acl, policy)
        eq(e.status, 400)
        eq(e.reason, 'Bad Request')
        # ECS return InvalidArgument
        eq(e.error_code, 'UnresolvableGrantByEmailAddress')

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acl_revoke_all() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acl_revoke_all(self):
        """
        operation: revoke all access, including the owner's access
        assertion: acls read back as empty
        """
        bucket = self._create_bucket()

        policy = bucket.get_acl()
        policy.acl.grants = []
        bucket.set_acl(policy)

        policy = bucket.get_acl()
        eq(len(policy.acl.grants), 0)

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_bucket_acls_changes_persistent() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acls_persistent(self):
        """
        operation: apply a set of acls
        assertion: all permissions are persistent
        """
        bucket = self._create_bucket()
        self._test_bucket_acls_changes_persistent(bucket)

    @triage
    @not_supported('fakes3')  # fakes3 bucket acl issue
    # port from test case: test_stress_bucket_acls_changes() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_bucket_acls_persistent_repeat(self):
        """
        operation: apply a set of acls repeatedly
        assertion: all permissions are persistent
        """
        bucket = self._create_bucket()
        for i in range(10):
            self._test_bucket_acls_changes_persistent(bucket)

    def _create_connection_bad_auth(self, aws_access_key_id='badauth'):
        # We're going to need to manually build a connection using
        # bad authorization info.

        conn = self.get_conn(aws_access_key_id=aws_access_key_id,
                             aws_secret_access_key='bad_access_key__')
        return conn

    @triage
    # awss3 issue: SAXParseException was raised when conn.get_all_buckets
    # ecs issue: S3ResponseError(400 Bad Request,
    #   NoNamespaceForAnonymousRequest) was raised when conn.get_all_buckets()
    @not_supported('awss3', 'ecs')
    # port from test case: test_list_buckets_anonymous() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_list_buckets_anonymous(self):
        """
        operation: list all buckets anonymously
        assertion: succeeds
        """
        # Get a connection with bad authorization, then change it to be our
        # new Anonymous auth mechanism, emulating standard HTTP access.
        #
        # While it may have been possible to use httplib directly, doing it
        # this way takes care of also allowing us to vary the calling format
        # in testing.

        class AnonymousAuthHandler(AuthHandler):
            def add_auth(self, http_request, **kwargs):
                return  # Nothing to do for anonymous access!

        conn = self._create_connection_bad_auth()
        conn._auth_handler = AnonymousAuthHandler(None, None, None)
        buckets = conn.get_all_buckets()
        eq(len(buckets), 0)

    @triage
    # fakes3 issue: S3ResponseError doesn't be raised when conn.get_all_buckets
    @not_supported('fakes3')
    # port from test case: test_list_buckets_invalid_auth() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_list_buckets_invalid_auth(self):
        """
        operation: list all buckets with bad key id
        assertion: fails with 403 error
        """

        conn = self._create_connection_bad_auth()
        e = assert_raises(S3ResponseError, conn.get_all_buckets)
        eq(e.status, 403)
        eq(e.reason, 'Forbidden')
        eq(e.error_code, 'InvalidAccessKeyId')

    @triage
    # fakes3 issue: S3ResponseError doesn't be raised when conn.get_all_buckets
    @not_supported('fakes3')
    # port from test case: test_list_buckets_bad_auth() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_list_buckets_bad_auth(self):
        """
        operation: list all buckets with bad access key
        assertion: fails with 403 error
        """

        conn = self._create_connection_bad_auth(
            aws_access_key_id=self.cfg['ACCESS_KEY'])
        e = assert_raises(S3ResponseError, conn.get_all_buckets)
        eq(e.status, 403)
        eq(e.reason, 'Forbidden')
        eq(e.error_code, 'SignatureDoesNotMatch')
