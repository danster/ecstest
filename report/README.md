#ecstest report

A test report for testing [EMC ECS](https://www.emc.com/storage/ecs-appliance/index.htm) deployments.

Some points need to be known before reading the documents in report folder.

- All test cases are ported from [cephs3test](https://github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py).
- Some test cases of cephs3test were not ported for some reasons, as follows:
  - **Blocked**: the test case which works under two test accounts.
  - **Disabled**: the test case which can't work correctly in any environment of awss3, fakes3, ecs at present.
  - **Skipped**: the test case which can't work owning to lacking some configuration parameters.
- The file `testcase_table.md` lists all test cases of ecstest and related test results on awss3, fakes3 and ecs.
- The file `ecs_issues.md` lists all ecs issues found when testing the test cases of ecstest.

The unported test cases of [cephs3test](https://github.com/ceph/s3-tests/blob/master/s3tests/functional/test_s3.py) list as follows:

|test case name| reason |
|--------------|--------|
|test_object_set_get_metadata_empty_to_unreadable_prefix|Disabled|
|test_object_set_get_metadata_empty_to_unreadable_suffix|Disabled|
|test_object_set_get_metadata_empty_to_unreadable_infix|Disabled|
|test_object_set_get_metadata_overwrite_to_unreadable_prefix|Disabled|
|test_object_set_get_metadata_overwrite_to_unreadable_suffix|Disabled|
|test_object_set_get_metadata_overwrite_to_unreadable_infix|Disabled|
|test_put_object_ifmatch_good|Disabled|
|test_put_object_ifmatch_failed|Disabled|
|test_put_object_ifmatch_overwrite_existed_good|Disabled|
|test_put_object_ifmatch_nonexisted_failed|Disabled|
|test_put_object_ifnonmatch_good|Disabled|
|test_put_object_ifnonmatch_failed|Disabled|
|test_put_object_ifnonmatch_nonexisted_good|Disabled|
|test_put_object_ifnonmatch_overwrite_existed_failed|Disabled|
|test_object_header_acl_grants|Disabled|
|test_bucket_delete_nonowner|Blocked|
|test_object_acl_canned_bucketownerread|Blocked|
|test_object_acl_canned_bucketownerfullcontrol|Blocked|
|test_object_acl_full_control_verify_owner|       Blocked|
|test_bucket_acl_grant_userid_fullcontrol|        Blocked|
|test_bucket_acl_grant_userid_read|               Blocked|
|test_bucket_acl_grant_userid_readacp|            Blocked|
|test_bucket_acl_grant_userid_write|              Blocked|
|test_bucket_acl_grant_userid_writeacp|           Blocked|
|test_bucket_header_acl_grants|                     Blocked|
|test_bucket_acl_grant_email|                       Blocked|
|test_access_bucket_private_object_private|         Blocked|
|test_access_bucket_private_object_publicread|      Blocked|
|test_access_bucket_private_object_publicreadwrite| Blocked|
|test_access_bucket_publicread_object_private|      Blocked|
|test_access_bucket_publicread_object_publicread|   Blocked|
|test_access_bucket_publicread_object_publicreadwrite|      Blocked|
|test_access_bucket_publicreadwrite_object_private|         Blocked|
|test_access_bucket_publicreadwrite_object_publicread|      Blocked|
|test_access_bucket_publicreadwrite_object_publicreadwrite| Blocked|
|test_object_giveaway|                                      Blocked|
|test_object_copy_not_owned_bucket|                         Blocked|
|test_region_bucket_create_secondary_access_remove_master|  Blocked|
|test_region_bucket_create_master_access_remove_secondary|  Blocked|
|test_region_copy_object|                                   Blocked|
|test_bucket_get_location|Skipped|