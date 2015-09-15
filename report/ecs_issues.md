|issue name|issue description| test case file name | test case name | comments|
|---|---|---|---|---|
|ecs Error|	the exception doesn't be raised when key.set\_contents\_from\_string	|bucket\_acl\_test.py|bucket\_acl\_no\_grants||
|ecs Error|	ecs returns 'InvalidArgument' but 'UnresolvableGrantByEmailAddress' when bucket.set\_acl(policy)|bucket\_acl\_test.py	|test\_bucket\_acl\_grant\_not\_exist\_email||
|ecs 400 Error|	S3ResponseError(400 Bad Request, NoNamespaceForAnonymousRequest) was raised when conn.get\_all\_buckets()	|bucket\_acl\_test.py|test\_list\_buckets\_anonymous||
|ecs 501 Error	|ecs returns '501 Not Implemented' when bucket.enable\_loggin()	|bucket\_access\_test.py|test\_logging\_toggle||
|ecs 409 Error|	ecs returns 409 Conflict, BucketAlreadyExists when taking some operations	|bucket\_create\_delete\_test.py|test\_bucket\_create\_exists<br>test\_bucket\_create\_exists\_not\_owner<br>test\_bucket\_recreate\_not\_overriding||
|ecs Error|S3ResponseError isn't raised and the bucket has be created|bucket\_create\_delete\_test.py	|test\_bucket\_create\_naming\_bad\_short||
|ecs versioning issue|	ecs returns 500 Server Error(InternalError) through bucket.configure\_versioning(True or False)|bucket\_object\_versioning\_test.py	|test\_versioning\_bucket\_create\_suspend<br>test\_versioning\_obj\_create\_read\_remove<br>test\_versioning\_obj\_create\_read\_remove\_head<br>test\_versioning\_obj\_suspend\_versions<br>test\_versioning\_obj\_create\_versions\_remove\_all<br>test\_versioning\_obj\_create\_overwrite\_multipart<br>test\_versioning\_obj\_list\_marker<br>test\_versioning\_copy\_obj\_version<br>test\_versioning\_multi\_object\_delete<br>test\_versioning\_multi\_object\_delete\_with\_marker<br>test\_versioning\_multi\_object\_delete\_with\_marker\_create<br>test\_versioned\_object\_acl<br>test\_versioned\_concurrent\_object\_create\_concurrent\_remove<br>test\_versioned\_concurrent\_object\_create\_and\_remove<br>||
|ecs marker issue	|the response Keys contain the marker, that is not consistent with aws-s3 which don't contain the marker.|object\_list\_test\_extend.py	| test\_object\_list\_many<br>test\_object\_list\_maxkeys\_one||
|ecs NextMarker issue|	the response NextMarker is not consistent with  aws-s3 that's NextMarker is the last element of Keys.|object\_list\_test\_extend.py	|test\_object\_list\_delimiter\_prefix||
|ecs 500 Error|	ecs returns '500 Internal Server Error'|object\_list\_test\_extend.py	|test\_object\_list\_maxkeys\_invalid||
|ecs Owner issue|	the response xml of listing objects of bucket doesn't contain the 'Owner' element, that is not consistent with aws-s3 which contains 'Owner'.	|object\_list\_test\_extend.py|test\_object\_list\_return\_data||
|ecs 400 Error|ecs returns 400 when 'PUT' or 'GET' request|object\_create\_delete\_test.py|test\_object\_raw\_get<br>test\_object\_raw\_get\_bucket\_gone<br>test\_object\_raw\_get\_object\_gone<br>test\_object\_raw\_get\_bucket\_acl<br>test\_object\_raw\_put<br>test\_object\_raw\_put\_write\_access<br>||
|ecs 400 Error|	ecs returns 400 when requests.post()|object\_post\_test.py	|test\_post\_object\_anonymous\_request<br>test\_post\_object\_authenticated\_request<br>test\_post\_object\_authenticated\_request\_bad\_access\_key<br>test\_post\_object\_set\_success\_code<br>test\_post\_object\_set\_invalid\_success\_code<br>test\_post\_object\_upload\_larger\_than\_chunk<br>test\_post\_object\_set\_key\_from\_filename<br>test\_post\_object\_ignored\_header<br>test\_post\_object\_case\_insensitive\_condition\_fields<br>test\_post\_object\_escaped\_field\_values<br>test\_post\_object\_success\_redirect\_action<br>test\_post\_object\_invalid\_signature<br>test\_post\_object\_invalid\_access\_key<br>test\_post\_object\_missing\_policy\_condition<br>test\_post\_object\_user\_specified\_header<br>test\_post\_object\_request\_missing\_policy\_specified\_field<br>test\_post\_object\_expired\_policy<br>test\_post\_object\_invalid\_request\_field\_value<br>||
|ecs cors issue|	ecs returns 400 error when requests.get, requests.put and requests.options|object\_acl\_test.py	|test\_cors\_origin\_response||
|ecs Error|ecs does not return S3ResponseError when upload.complete\_upload|	object\_multipart\_test.py|test\_multipart\_upload\_size\_too\_small||
|ecs 400 Error|ecs returns 400 InvalidRequest when upload.complete\_upload|object\_multipart\_test.py|test\_multipart\_upload\_empty||
|ecs Error|ecs does not return S3ResponseError when upload.complete\_upload|object\_multipart\_test.py|test\_abort\_multipart\_upload<br>test\_list\_multipart\_upload||


####tips
 
- `issue name` column just describes the issue briefly, which isn't regular.

