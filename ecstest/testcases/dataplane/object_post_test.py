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

import base64
import collections
import datetime
import hmac
import json
import requests
import xml.etree.ElementTree as ET

from nose.plugins.attrib import attr
from nose.tools import eq_ as eq
import pytz

from ecstest import tag
from ecstest import testbase
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


@attr(tags=[tag.DATA_PLANE, tag.OBJECT_IO])
class TestObjectPutPost(testbase.EcsDataPlaneTestBase):
    """
    Test the post operations to object
    """

    def setUp(self):
        super(TestObjectPutPost, self).setUp(create_bucket=True)

    def tearDown(self):
        super(TestObjectPutPost, self).tearDown()

    def _get_policy_signature(self, policy_doc):
        """
        Return policy and signature
        """
        json_policy_document = json.JSONEncoder().encode(policy_doc)
        policy = base64.b64encode(bytes(json_policy_document, 'UTF-8'))
        signature = base64.b64encode(
            hmac.new(bytes(self.data_conn.aws_secret_access_key, 'UTF-8'),
                     policy, 'sha1').digest())

        return policy, signature

    @triage
    # ecs 400 issue: ecs always returns 400 error when requests.post()
    @not_supported('ecs')
    # port from test case:
    #   test_post_object_anonymous_request() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_anonymous_request(self):
        """
        operation: anonymous browser based upload via POST request
        assertion: succeeds and returns written data
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        bucket.set_acl('public-read-write')

        payload = collections.OrderedDict([("key", "foo.txt"),
                                           ("acl", "public-read"),
                                           ("Content-Type", "text/plain"),
                                           ('file', 'bar')])

        r = requests.post(url, files=payload)
        # ecs returns 400
        eq(r.status_code, 204)
        key = bucket.get_key("foo.txt")
        got = key.get_contents_as_string()
        eq(got, b'bar')

    @triage
    @not_supported('ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_authenticated_request() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_authenticated_request(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: succeeds and returns written data
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"],
                                     ["content-length-range", 0, 1024]]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # ecs returns 400
        eq(r.status_code, 204)
        key = bucket.get_key("foo.txt")
        got = key.get_contents_as_string()
        eq(got, b'bar')

    @triage
    # fakes3 returns 204 but 403 when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_authenticated_request_bad_access_key() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_authenticated_request_bad_access_key(self):
        """
        operation: authenticated browser based upload via POST request,
                   bad access key.
        assertion: fails
        """
        bucket = self.bucket
        bucket.set_acl('public-read-write')
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", 'foo'),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204, ecs returns 400
        eq(r.status_code, 403)

    @triage
    @not_supported('ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_set_success_code() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_set_success_code(self):
        """
        operation: anonymous browser based upload via POST request
        assertion: succeeds with status 201
        """
        bucket = self.bucket
        bucket.set_acl('public-read-write')
        url = _get_post_url(self.data_conn, bucket)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("acl", "public-read"),
             ("success_action_status", "201"),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # ecs returns 400
        eq(r.status_code, 201)
        message = ET.fromstring(r.content).find('Key')
        eq(message.text, 'foo.txt')

    @triage
    # fakes3 returns 404 but 204 when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_set_invalid_success_code() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_set_invalid_success_code(self):
        """
        operation: anonymous browser based upload via POST request
        assertion: succeeds with status 204
        """
        bucket = self.bucket
        bucket.set_acl('public-read-write')
        url = _get_post_url(self.data_conn, bucket)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("acl", "public-read"),
             ("success_action_status", "404"),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 404, ecs returns 400
        eq(r.status_code, 204)
        eq(r.content, b'')

    @triage
    @not_supported('ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_upload_larger_than_chunk() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_upload_larger_than_chunk(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: succeeds and returns written data
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 5*1024*1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)
        foo_string = 'foo' * 1024*1024

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', foo_string)
             ])

        r = requests.post(url, files=payload)
        # ecs returns 400
        eq(r.status_code, 204)
        key = bucket.get_key("foo.txt")
        got = key.get_contents_as_string()
        eq(got.decode('utf-8'), foo_string)

    @triage
    # fakes3 returns None when bucket.get_key("foo.txt")
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_set_key_from_filename() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_set_key_from_filename(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: succeeds and returns written data
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 5*1024*1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "${filename}"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', ('foo.txt', 'bar'))
             ])

        r = requests.post(url, files=payload)
        # ecs returns 400
        eq(r.status_code, 204)

        # fakes3 returns None
        key = bucket.get_key("foo.txt")
        got = key.get_contents_as_string()
        eq(got, b'bar')

    @triage
    @not_supported('ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_ignored_header() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_ignored_header(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: succeeds with status 204
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ("x-ignore-foo", "bar"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)

        # ECS return 400, ecs returns 400
        eq(r.status_code, 204)

    @triage
    # fakes3 returns 500 but 204 when requests.post()
    @not_supported('ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_case_insensitive_condition_fields() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_case_insensitive_condition_fields(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: succeeds with status 204
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bUcKeT": bucket.name},
                                     ["StArTs-WiTh", "$KeY", "foo"],
                                     {"AcL": "private"},
                                     ["StArTs-WiTh",
                                      "$CoNtEnT-TyPe",
                                      "text/plain"],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }
        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("kEy", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("aCl", "private"),
             ("signature", signature),
             ("pOLICy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 500, ecs returns 400
        eq(r.status_code, 204)

    @triage
    @not_supported('ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_escaped_field_values() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_escaped_field_values(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: succeeds with escaped leading $ and returns written data
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "\$foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "\$foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # ecs returns 400
        eq(r.status_code, 204)
        key = bucket.get_key("\$foo.txt")
        got = key.get_contents_as_string()
        eq(got, b'bar')

    @triage
    # fakes3 gets requests.exceptions.TooManyRedirects when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_success_redirect_action() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_success_redirect_action(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: succeeds and returns redirect url
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        redirect_url = _get_post_url(self.data_conn, bucket)
        bucket.set_acl('public-read')
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with", "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["eq", "$success_action_redirect",
                                      redirect_url],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ("success_action_redirect", redirect_url),
             ('file', 'bar')
             ])

        # fakes3: requests.exceptions.TooManyRedirects, Exceeded 30 redirects.
        r = requests.post(url, files=payload)
        # ecs returns 400
        eq(r.status_code, 200)
        url = r.url
        key = bucket.get_key("foo.txt")
        eq(url, '{rurl}?bucket={bucket}&key={key}&etag=%22{etag}%22'.format(
            rurl=redirect_url,
            bucket=bucket.name,
            key=key.name,
            etag=key.etag.strip('"')))

    @triage
    # fakes3 returns 204 but 403 when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_invalid_signature() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_invalid_signature(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with invalid signature error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "\$foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "\$foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature[::-1]),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204, ecs returns 400
        eq(r.status_code, 403)

    @triage
    # fakes3 returns 204 but 403 when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_invalid_access_key() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_invalid_access_key(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with access key does not exist error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "\$foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "\$foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id[::-1]),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204, ecs returns 400
        eq(r.status_code, 403)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_invalid_date_format() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_invalid_date_format(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with invalid expiration error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": str(expire),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "\$foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "\$foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 500 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_no_key_specified() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_no_key_specified(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with missing key error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)

        # fakes3 returns 500
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_missing_signature() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_missing_signature(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with missing signature error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "\$foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, _signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "\$foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 403 when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_missing_policy_condition() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_missing_policy_condition(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with extra input fields policy error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024],
                                     ["starts-with", "$x-amz-meta-foo",  "bar"]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)

        # fakes3 returns 204, ecs returns 400
        eq(r.status_code, 403)

    @triage
    # fakes3 returns None when key.get_metadata('foo')
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_user_specified_header() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_user_specified_header(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: succeeds using starts-with restriction on metadata header
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024],
                                     ["starts-with", "$x-amz-meta-foo",  "bar"]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('x-amz-meta-foo', 'barclamp'),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # ecs returns 400
        eq(r.status_code, 204)
        key = bucket.get_key("foo.txt")
        # fakes3 returns None when key.get_metadata()
        eq(key.get_metadata('foo'), 'barclamp')

    @triage
    # fakes3 returns 204 but 403 when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_request_missing_policy_specified_field() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_request_missing_policy_specified_field(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with policy condition failed error
                   due to missing field in POST request.
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024],
                                     ["starts-with", "$x-amz-meta-foo",  "bar"]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204, ecs returns 400
        eq(r.status_code, 403)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_condition_is_case_sensitive() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_condition_is_case_sensitive(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with conditions must be list error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "CONDITIONS": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_expires_is_case_sensitive() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_expires_is_case_sensitive(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with expiration must be string error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"EXPIRATION": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 403 when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_expired_policy() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_expired_policy(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with policy expired error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=-6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204, ecs returns 400
        eq(r.status_code, 403)

    @triage
    # fakes3 returns 204 but 403 when requests.post()
    @not_supported('fakes3', 'ecs')  # ecs 400 issue
    # port from test case:
    #   test_post_object_invalid_request_field_value() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_invalid_request_field_value(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails using equality restriction on metadata header
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024],
                                     ["eq", "$x-amz-meta-foo",  ""]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('x-amz-meta-foo', 'barclamp'),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204, ecs returns 400
        eq(r.status_code, 403)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_missing_expires_condition() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_missing_expires_condition(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with policy missing expiration error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)

        policy_doc = {"conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_missing_conditions_list() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_missing_conditions_list(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with policy missing conditions error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ")}

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_upload_size_limit_exceeded() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_upload_size_limit_exceeded(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with allowable upload size exceeded error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0, 0]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_missing_content_length_argument() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_missing_content_length_argument(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with invalid content length error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 0]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_invalid_content_length_argument() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_invalid_content_length_argument(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with invalid JSON error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", -1, 0]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)

    @triage
    # fakes3 returns 204 but 400 when requests.post()
    @not_supported('fakes3')
    # port from test case:
    #   test_post_object_upload_size_below_minimum() of https://
    #   github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py
    def test_post_object_upload_size_below_minimum(self):
        """
        operation: authenticated browser based upload via POST request
        assertion: fails with upload size less than minimum allowable error
        """
        bucket = self.bucket
        url = _get_post_url(self.data_conn, bucket)
        utc = pytz.utc
        expire = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

        policy_doc = {"expiration": expire.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "conditions": [{"bucket": bucket.name},
                                     ["starts-with", "$key", "foo"],
                                     {"acl": "private"},
                                     ["starts-with",
                                      "$Content-Type",
                                      "text/plain"
                                      ],
                                     ["content-length-range", 512, 1024]
                                     ]
                      }

        policy, signature = self._get_policy_signature(policy_doc)

        payload = collections.OrderedDict(
            [("key", "foo.txt"),
             ("AWSAccessKeyId", self.data_conn.aws_access_key_id),
             ("acl", "private"),
             ("signature", signature),
             ("policy", policy),
             ("Content-Type", "text/plain"),
             ('file', 'bar')
             ])

        r = requests.post(url, files=payload)
        # fakes3 returns 204
        eq(r.status_code, 400)
