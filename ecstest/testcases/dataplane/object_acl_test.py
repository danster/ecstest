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

import time

import bunch
from boto.exception import S3ResponseError
from boto.s3.acl import ACL
from boto.s3.cors import CORSConfiguration
from nose.plugins.attrib import attr
from nose.tools import eq_ as eq
import requests

from ecstest import keyname
from ecstest import tag
from ecstest import testbase
from ecstest.cephs3utils import assert_raises
from ecstest.cephs3utils import check_grants
from ecstest.dec import not_supported
from ecstest.dec import triage


def _get_post_url(conn, bucket):

    url = '{protocol}://{host}:{port}/{bucket}'.format(
        protocol='https' if conn.is_secure else 'http',
        host=conn.host,
        port=conn.port,
        bucket=bucket.name
    )

    return url


def _make_acl_xml(user_id, acl):
    """
    Return the xml form of an ACL entry
    """
    return '<?xml version="1.0" encoding="UTF-8"?><AccessControlPolicy ' \
           'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>' + \
           user_id + '</ID></Owner>' + acl.to_xml() + '</AccessControlPolicy>'


def _cors_request_and_check(func, url, headers, expect_status,
                            expect_allow_origin, expect_allow_methods):

    r = func(url, headers=headers)
    eq(r.status_code, expect_status)

    if 'access-control-allow-origin' in r.headers:
        eq(r.headers['access-control-allow-origin'], expect_allow_origin)
    else:
        eq(None, expect_allow_origin)

    if 'access-control-allow-methods' in r.headers:
        eq(r.headers['access-control-allow-methods'], expect_allow_methods)
    else:
        eq(None, expect_allow_methods)


@attr(tags=[tag.DATA_PLANE, tag.KEY_MGMT])
class TestObjectACL(testbase.EcsDataPlaneTestBase):
    """
    Test the ACLs of objects
    """

    def setUp(self):
        super(TestObjectACL, self).setUp(create_bucket=True)

    def tearDown(self):
        super(TestObjectACL, self).tearDown()

    # port from function: _build_object_acl_xml() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def _build_object_acl_xml(self, permission):
        """
        add the specified permission for the current user to
        a new object in a new bucket, in XML form, set it, and
        then read it back to confirm it was correctly set
        """
        acl = ACL()

        # get the user id from an existed key
        key_name1 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name1)
        key.set_contents_from_string(key_name1)
        user_id = key.get_acl().owner.id

        acl.add_user_grant(permission=permission, user_id=user_id)
        XML = _make_acl_xml(user_id=user_id, acl=acl)

        key_name2 = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name2)
        key.set_contents_from_string(key_name2)

        key.set_xml_acl(XML)
        policy = key.get_acl()

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

    @triage
    # port from test case: test_object_acl_default() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_default(self):
        """
        operation: get default object acl after creating it
        assertion: grants of acl match what we want
        """

        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        policy = key.get_acl()
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
    # fakes3 issue: grants only contain 'FULL_CONTROL' permission
    @not_supported('fakes3')
    # port from test case: test_object_acl_canned_during_create() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_after_create_object(self):
        """
        operation: get object acl after creating it with 'public-read' policy
        assertion: grants of acl match what we want
        """

        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name, policy='public-read')

        policy = key.get_acl()
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
    # fakes3 issue: grants only contain 'FULL_CONTROL' permission
    @not_supported('fakes3')
    # port from test case: test_object_acl_canned() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_after_set_acl_publicread(self):
        """
        operation: get object acl after setting it 'public-read'
        assertion: grants of acl match what we want
        """

        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        # Since it defaults to private, set it public-read first
        key.set_acl('public-read')
        policy = key.get_acl()
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
        key.set_acl('private')
        policy = key.get_acl()
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
    # fakes3 issue: grants only contain 'FULL_CONTROL' permission
    @not_supported('fakes3')
    # port from test case: test_object_acl_canned_publicreadwrite() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_after_set_acl_publicreadwrite(self):
        """
        operation: get object acl after setting it 'public-read-write'
        assertion: grants of acl match what we want
        """

        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        key.set_acl('public-read-write')
        policy = key.get_acl()
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
    # fakes3 issue: grants only contain 'FULL_CONTROL' permission
    @not_supported('fakes3')
    # port from test case:
    #   test_object_acl_canned_authenticatedread() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_after_set_acl_authenticatedread(self):
        """
        operation: get object acl after setting it 'authenticated-read'
        assertion: grants of acl match what we want
        """

        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name)

        key.set_acl('authenticated-read')
        policy = key.get_acl()
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
                    uri='http://acs.amazonaws.com/groups/'
                        'global/AuthenticatedUsers',
                    email_address=None,
                    type='Group',
                    ),
                ],
            )

    @triage
    # port from test case: test_object_acl_xml() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_xml(self):
        """
        operation: set the acl of object to 'FULL_CONTROL' by xml format
        assertion: grants got from object match what we set previously
        """
        self._build_object_acl_xml('FULL_CONTROL')

    @triage
    # fakes3 returns 'FULL_CONTROL' but 'WRITE'
    @not_supported('fakes3')
    # port from test case: test_object_acl_xml_write() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_xml_write(self):
        """
        operation: set the acl of object to 'WRITE' by xml format
        assertion: grants got from object match what we set previously
        """
        self._build_object_acl_xml('WRITE')

    @triage
    # port from test case: test_object_acl_xml_writeacp() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_xml_writeacp(self):
        """
        operation: set the acl of object to 'WRITE_ACP' by xml format
        assertion: grants got from object match what we set previously
        """
        self._build_object_acl_xml('WRITE_ACP')

    @triage
    # fakes3 returns 'FULL_CONTROL' but 'READ'
    @not_supported('fakes3')
    # port from test case: test_object_acl_xml_read() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_xml_read(self):
        """
        operation: set the acl of object to 'READ' by xml format
        assertion: grants got from object match what we set previously
        """
        self._build_object_acl_xml('READ')

    @triage
    # fakes3 returns 'FULL_CONTROL' but 'READ_ACP'
    @not_supported('fakes3')
    # port from test case: test_object_acl_xml_readacp() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_acl_xml_readacp(self):
        """
        operation: set the acl of object to 'READ_ACP' by xml format
        assertion: grants got from object match what we set previously
        """
        self._build_object_acl_xml('READ_ACP')

    @triage
    # port from test case: test_object_set_valid_acl() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_object_set_valid_acl(self):
        """
        operation: set object acls
        assertion: valid XML ACL sets properly
        """
        key_name = keyname.get_unique_key_name()
        key = self.bucket.new_key(key_name)
        key.set_contents_from_string(key_name)
        user_id = key.get_acl().owner.id

        xml = '<?xml version="1.0" encoding="UTF-8"?><AccessControlPolicy ' \
              'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>' + \
              user_id + '</ID></Owner><AccessControlList><Grant><Grantee ' \
                        'xmlns:xsi="http://www.w3.org/2001/' \
                        'XMLSchema-instance" xsi:type="CanonicalUser"><ID>' + \
              user_id + '</ID></Grantee><Permission>FULL_CONTROL' \
                        '</Permission></Grant></AccessControlList>' \
                        '</AccessControlPolicy>'

        key.set_xml_acl(xml)

    @triage
    # fakes3 cors issue: S3ResponseError isn't raised when bucket.get_cors()
    # although bucket has no core configure;  fakes3 returns empty cors
    # configures when bucket.get_cors() although bucket has core configures.
    @not_supported('fakes3')
    # port from test case: test_set_cors() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_set_cors(self):
        """
        operation: create a cors configure and set the cors to a bucket
        assertion: cors works on the bucket
        """

        bucket = self.bucket
        cfg = CORSConfiguration()
        cfg.add_rule('GET', '*.get')
        cfg.add_rule('PUT', '*.put')

        # e = assert_raises(S3ResponseError, bucket.get_cors)
        # eq(e.status, 404)

        bucket.set_cors(cfg)
        new_cfg = bucket.get_cors()

        eq(len(new_cfg), 2)

        result = bunch.Bunch()

        for c in new_cfg:
            eq(len(c.allowed_method), 1)
            eq(len(c.allowed_origin), 1)
            result[c.allowed_method[0]] = c.allowed_origin[0]

        eq(result['GET'], '*.get')
        eq(result['PUT'], '*.put')

        bucket.delete_cors()

        e = assert_raises(S3ResponseError, bucket.get_cors)
        eq(e.status, 404)

    @triage
    # ecs cors issue: ecs returns 400 error when requests.get, requests.put
    #   and requests.options
    @not_supported('fakes3', 'ecs')  # fakes3 cors issue
    # port from test case: test_cors_origin_response() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_cors_origin_response(self):
        """
        operation: checks cors response when origin header set
        assertion: returns cors header
        """

        cfg = CORSConfiguration()
        bucket = self.bucket
        bucket.set_acl('public-read')

        cfg.add_rule('GET', '*suffix')
        cfg.add_rule('GET', 'start*end')
        cfg.add_rule('GET', 'prefix*')
        cfg.add_rule('PUT', '*.put')

        e = assert_raises(S3ResponseError, bucket.get_cors)
        eq(e.status, 404)

        bucket.set_cors(cfg)

        # waiting, since if running against amazon data consistency model
        # is not strict read-after-write
        time.sleep(3)

        post_url = _get_post_url(self.data_conn, bucket)
        obj_url = '{u}/{o}'.format(u=post_url, o='bar')

        # ecs returns 400 when requests.get
        _cors_request_and_check(requests.get, post_url, None, 200, None, None)
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'foo.suffix'},
                                200, 'foo.suffix', 'GET')
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'foo.bar'},
                                200, None, None)
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'foo.suffix.get'},
                                200, None, None)
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'startend'},
                                200, 'startend', 'GET')
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'start1end'},
                                200, 'start1end', 'GET')
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'start12end'},
                                200, 'start12end', 'GET')
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': '0start12end'},
                                200, None, None)
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'prefix'},
                                200, 'prefix', 'GET')
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'prefix.suffix'},
                                200, 'prefix.suffix', 'GET')
        _cors_request_and_check(requests.get, post_url,
                                {'Origin': 'bla.prefix'},
                                200, None, None)
        _cors_request_and_check(requests.get, obj_url,
                                {'Origin': 'foo.suffix'},
                                404, 'foo.suffix', 'GET')
        _cors_request_and_check(requests.get, obj_url,
                                {'Origin': 'foo.suffix'},
                                404, 'foo.suffix', 'GET')

        # ecs returns 400 when requests.put
        _cors_request_and_check(requests.put, obj_url,
                                {'Origin': 'foo.suffix',
                                 'Access-Control-Request-Method': 'GET',
                                 'content-length': '0'},
                                403, 'foo.suffix', 'GET')
        _cors_request_and_check(requests.put, obj_url,
                                {'Origin': 'foo.suffix',
                                 'Access-Control-Request-Method': 'PUT',
                                 'content-length': '0'},
                                403, None, None)
        _cors_request_and_check(requests.put, obj_url,
                                {'Origin': 'foo.suffix',
                                 'Access-Control-Request-Method': 'DELETE',
                                 'content-length': '0'},
                                403, None, None)
        _cors_request_and_check(requests.put, obj_url,
                                {'Origin': 'foo.suffix',
                                 'content-length': '0'},
                                403, None, None)
        _cors_request_and_check(requests.put, obj_url,
                                {'Origin': 'foo.put',
                                 'content-length': '0'},
                                403, 'foo.put', 'PUT')

        # ecs returns 400 when requests.options
        _cors_request_and_check(requests.options, post_url, None,
                                400, None, None)
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'foo.suffix'},
                                400, None, None)
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'bla'},
                                400, None, None)
        _cors_request_and_check(requests.options, obj_url,
                                {'Origin': 'foo.suffix',
                                 'Access-Control-Request-Method': 'GET',
                                 'content-length': '0'},
                                200, 'foo.suffix', 'GET')
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'foo.bar',
                                 'Access-Control-Request-Method': 'GET'},
                                403, None, None)
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'foo.suffix.get',
                                 'Access-Control-Request-Method': 'GET'},
                                403, None, None)
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'startend',
                                 'Access-Control-Request-Method': 'GET'},
                                200, 'startend', 'GET')
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'start1end',
                                 'Access-Control-Request-Method': 'GET'},
                                200, 'start1end', 'GET')
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'start12end',
                                 'Access-Control-Request-Method': 'GET'},
                                200, 'start12end', 'GET')
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': '0start12end',
                                 'Access-Control-Request-Method': 'GET'},
                                403, None, None)
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'prefix',
                                 'Access-Control-Request-Method': 'GET'},
                                200, 'prefix', 'GET')
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'prefix.suffix',
                                 'Access-Control-Request-Method': 'GET'},
                                200, 'prefix.suffix', 'GET')
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'bla.prefix',
                                 'Access-Control-Request-Method': 'GET'},
                                403, None, None)
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'foo.put',
                                 'Access-Control-Request-Method': 'GET'},
                                403, None, None)
        _cors_request_and_check(requests.options, post_url,
                                {'Origin': 'foo.put',
                                 'Access-Control-Request-Method': 'PUT'},
                                200, 'foo.put', 'PUT')
