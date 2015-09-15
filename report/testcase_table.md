| test case file name | test case name | port from | support awss3 | support fakes3 | support ecs | comments |
|-------------|-----------|------------|-----------|------|------|------|
| bucket\_access\_test.py | test\_bucket\_not\_exist | test\_bucket\_notexist |Y|Y|Y||
| bucket\_access\_test.py | test\_bucket\_delete\_not\_exist | test\_bucket\_delete\_notexist |Y|N|Y||
| bucket\_access\_test.py | test\_bucket\_delete\_not\_empty | test\_bucket\_delete\_nonempty |Y|N|Y||
| bucket\_access\_test.py | test\_object\_write\_to\_not\_exist\_bucket | test\_object\_write\_to\_nonexist\_bucket |Y|N|Y||
| bucket\_access\_test.py | test\_bucket\_delete\_deleted\_bucket | test\_bucket\_create\_delete |Y|N|Y||
| bucket\_access\_test.py | test\_bucket\_head | test\_bucket\_head\_extended |Y|Y|Y||
| bucket\_access\_test.py | test\_logging\_toggle | test\_logging\_toggle |Y|N|N||
| bucket\_acl\_test.py |test\_bucket\_acl\_default|test\_bucket\_acl\_default|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_after\_create\_bucket|test\_bucket\_acl\_canned\_during\_create|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_after\_set\_acl\_publicread|test\_bucket\_acl\_canned|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_after\_set\_acl\_publicreadwrite|test\_bucket\_acl\_canned\_publicreadwrite|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_after\_set\_acl\_authenticatedread|test\_bucket\_acl\_canned\_authenticatedread|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_set\_private\_to\_private|test\_bucket\_acl\_canned\_private\_to\_private|Y|Y|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_xml\_fullcontrol|test\_bucket\_acl\_xml\_fullcontrol|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_xml\_write|test\_bucket\_acl\_xml\_write|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_xml\_writeacp|test\_bucket\_acl\_xml\_writeacp|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_xml\_read|test\_bucket\_acl\_xml\_read|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_xml\_readacp|test\_bucket\_acl\_xml\_readacp|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_grant\_not\_exist\_user|test\_bucket\_acl\_grant\_nonexist\_user|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acl\_no\_grants|test\_bucket\_acl\_no\_grants|Y|N|N||
| bucket\_acl\_test.py |test\_bucket\_acl\_grant\_not\_exist\_email|test\_bucket\_acl\_grant\_email\_notexist|Y|N|N||
| bucket\_acl\_test.py |test\_bucket\_acl\_revoke\_all|test\_bucket\_acl\_revoke\_all|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acls\_persistent|test\_bucket\_acls\_changes\_persistent|Y|N|Y||
| bucket\_acl\_test.py |test\_bucket\_acls\_persistent\_repeat|test\_stress\_bucket\_acls\_changes|Y|N|Y||
| bucket\_acl\_test.py |test\_list\_buckets\_anonymous|test\_list\_buckets\_anonymous|Y|N|N||
| bucket\_acl\_test.py |test\_list\_buckets\_invalid\_auth|test\_list\_buckets\_invalid\_auth|Y|N|Y||
| bucket\_acl\_test.py |test\_list\_buckets\_bad\_auth|test\_list\_buckets\_bad\_auth|Y|N|Y||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_naming\_bad\_short|test\_bucket\_create\_naming\_bad\_short\_empty <br>test\_bucket\_create\_naming\_bad\_short\_one<br>test\_bucket\_create\_naming\_bad\_short\_two|Y|N|N||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_naming\_bad\_long|test\_bucket\_create\_naming\_bad\_long|Y|N|Y||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_naming\_bad\_ip|test\_bucket\_create\_naming\_bad\_ip|Y|N|N||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_naming\_bad\_punctuation|test\_bucket\_create\_naming\_bad\_punctuation|Y|N|Y||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_naming\_good\_long|test\_bucket\_create\_naming\_good\_long\_250<br>test\_bucket\_create\_naming\_good\_long\_251<br>test\_bucket\_create\_naming\_good\_long\_252<br>test\_bucket\_create\_naming\_good\_long\_253<br>test\_bucket\_create\_naming\_good\_long\_254<br>test\_bucket\_create\_naming\_good\_long\_255|Y|Y|Y||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_naming\_good\_chars|test\_bucket\_create\_naming\_good\_starts\_alpha<br>test\_bucket\_create\_naming\_good\_starts\_digit<br>test\_bucket\_create\_naming\_good\_contains\_period<br>test\_bucket\_create\_naming\_good\_contains\_hyphen|Y|Y|Y||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_naming\_good\_starts\_nonalpha|test\_bucket\_create\_naming\_bad\_starts\_nonalpha|Y|Y|Y||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_naming\_dns|test\_bucket\_create\_naming\_dns\_underscore<br>test\_bucket\_create\_naming\_dns\_dash\_at\_end<br>test\_bucket\_create\_naming\_dns\_dot\_dot<br>test\_bucket\_create\_naming\_dns\_dot\_dash<br>test\_bucket\_create\_naming\_dns\_dash\_dot<br>test\_bucket\_create\_naming\_dns\_long|Y|Y|Y||
|bucket\_create\_delete\_test.py|test\_bucket\_list\_long\_name|test\_bucket\_list\_long\_name|Y|Y|Y||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_exists|test\_bucket\_create\_exists|Y|Y|N||
|bucket\_create\_delete\_test.py|test\_bucket\_create\_exists\_not\_owner|test\_bucket\_create\_exists\_nonowner|Y|Y|N||
|bucket\_create\_delete\_test.py|test\_bucket\_recreate\_not\_overriding|test\_bucket\_recreate\_not\_overriding|Y|Y|N||
|bucket\_create\_delete\_test.py|test\_buckets\_create\_then\_list|test\_buckets\_create\_then\_list|Y|Y|Y||
|bucket\_object\_versioning\_test.py|test\_versioning\_bucket\_create\_suspend|test\_versioning\_bucket\_create\_suspend|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_obj\_create\_read\_remove|test\_versioning\_obj\_create\_read\_remove|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_obj\_create\_read\_remove\_head|test\_versioning\_obj\_create\_read\_remove\_head|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_obj\_suspend\_versions|test\_versioning\_obj\_suspend\_versions<br>test\_versioning\_obj\_suspend\_versions\_simple|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_obj\_create\_versions\_remove\_all|test\_versioning\_obj\_create\_versions\_remove\_all|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_obj\_create\_overwrite\_multipart|test\_versioning\_obj\_create\_overwrite\_multipart|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_obj\_list\_marker|test\_versioning\_obj\_list\_marker|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_copy\_obj\_version|test\_versioning\_copy\_obj\_version|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_multi\_object\_delete|test\_versioning\_multi\_object\_delete|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_multi\_object\_delete\_with\_marker|test\_versioning\_multi\_object\_delete\_with\_marker|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioning\_multi\_object\_delete\_with\_marker\_create|test\_versioning\_multi\_object\_delete\_with\_marker\_create|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioned\_object\_acl|test\_versioned\_object\_acl|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioned\_concurrent\_object\_create\_concurrent\_remove|test\_versioned\_concurrent\_object\_create\_concurrent\_remove|Y|N|N||
|bucket\_object\_versioning\_test.py|test\_versioned\_concurrent\_object\_create\_and\_remove|test\_versioned\_concurrent\_object\_create\_and\_remove|Y|N|N||
|object\_access\_test.py|test\_ranged\_request\_response\_code|test\_ranged\_request\_response\_code|Y|Y|Y||
|object\_access\_test.py|test\_ranged\_request\_skip\_leading\_bytes\_response\_code|test\_ranged\_request\_skip\_leading\_bytes\_response\_code|Y|Y|Y||
|object\_access\_test.py|test\_ranged\_request\_return\_trailing\_bytes\_response\_code|test\_ranged\_request\_return\_trailing\_bytes\_response\_code|Y|N|Y||
|object\_access\_test.py|test\_atomic\_read|test\_atomic\_read\_1mb<br>test\_atomic\_read\_4mb<br>test\_atomic\_read\_8mb|Y|N|Y||
|object\_access\_test.py|test\_atomic\_write|test\_atomic\_write\_1mb<br>test\_atomic\_write\_4mb<br>test\_atomic\_write\_8mb|Y|Y|Y||
|object\_access\_test.py|test\_atomic\_dual\_write|test\_atomic\_dual\_write\_1mb<br>test\_atomic\_dual\_write\_4mb<br>test\_atomic\_dual\_write\_8mb|Y|Y|Y||
|object\_access\_test.py|test\_atomic\_conditional\_write|test\_atomic\_conditional\_write\_1mb|N|Y|Y||
|object\_access\_test.py|test\_atomic\_dual\_conditional\_write|test\_atomic\_dual\_conditional\_write\_1mb|N|Y|Y||
|object\_access\_test.py|test\_atomic\_write\_bucket\_gone|test\_atomic\_write\_bucket\_gone|N|Y|Y||
|object\_access\_test.py|test\_object\_read\_notexist|test\_object\_read\_notexist|Y|Y|Y||
|object\_access\_test.py|test\_object\_create\_special\_characters|test\_object\_create\_special\_characters<br>test\_object\_create\_unreadable|Y|Y|Y||
|object\_access\_test.py|test\_multi\_object\_delete|test\_multi\_object\_delete|Y|N|Y||
|object\_access\_test.py|test\_object\_write\_check\_etag|test\_object\_write\_check\_etag|Y|Y|Y||
|object\_access\_test.py|test\_object\_write\_read\_update\_read\_delete|test\_object\_write\_read\_update\_read\_delete|Y|Y|Y||
|object\_access\_test.py|test\_object\_set\_get\_metadata\_write\_to\_read|test\_object\_set\_get\_metadata\_none\_to\_good<br>test\_object\_set\_get\_metadata\_none\_to\_empty|Y|N|Y||
|object\_access\_test.py|test\_object\_set\_get\_metadata\_overwrite|test\_object\_set\_get\_metadata\_overwrite\_to\_good<br>test\_object\_set\_get\_metadata\_overwrite\_to\_empty|Y|N|Y||
|object\_access\_test.py|test\_object\_set\_get\_metadata\_unicode|test\_object\_set\_get\_unicode\_metadata<br>test\_object\_set\_get\_non\_utf8\_metadata|Y|N|Y||
|object\_access\_test.py|test\_object\_metadata\_replaced\_on\_put|test\_object\_metadata\_replaced\_on\_put|Y|Y|Y||
|object\_access\_test.py|test\_100\_continue|test\_100\_continue|Y|N|N||
|object\_acl\_test.py|test\_object\_acl\_default|test\_object\_acl\_default|Y|Y|Y||
|object\_acl\_test.py|test\_object\_acl\_after\_create\_object|test\_object\_acl\_canned\_during\_create|Y|N|Y||
|object\_acl\_test.py|test\_object\_acl\_after\_set\_acl\_publicread|test\_object\_acl\_canned|Y|N|Y||
|object\_acl\_test.py|test\_object\_acl\_after\_set\_acl\_publicreadwrite|test\_object\_acl\_canned\_publicreadwrite|Y|N|Y||
|object\_acl\_test.py|test\_object\_acl\_after\_set\_acl\_authenticatedread|test\_object\_acl\_canned\_authenticatedread|Y|N|Y||
|object\_acl\_test.py|test\_object\_acl\_xml|test\_object\_acl\_xml|Y|Y|Y||
|object\_acl\_test.py|test\_object\_acl\_xml\_write|test\_object\_acl\_xml\_write|Y|N|Y||
|object\_acl\_test.py|test\_object\_acl\_xml\_writeacp|test\_object\_acl\_xml\_writeacp|Y|Y|Y||
|object\_acl\_test.py|test\_object\_acl\_xml\_read|test\_object\_acl\_xml\_read|Y|N|Y||
|object\_acl\_test.py|test\_object\_acl\_xml\_readacp|test\_object\_acl\_xml\_readacp|Y|N|Y||
|object\_acl\_test.py|test\_object\_set\_valid\_acl|test\_object\_set\_valid\_acl|Y|Y|Y||
|object\_acl\_test.py|test\_set\_cors|test\_set\_cors|Y|N|Y||
|object\_acl\_test.py|test\_cors\_origin\_response|test\_cors\_origin\_response|Y|N|N||
|object\_create\_delete\_test.py|test\_object\_write\_file|test\_object\_write\_file|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_copy\_zero\_size|test\_object\_copy\_zero\_size|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_copy\_same\_bucket|test\_object\_copy\_same\_bucket|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_copy\_to\_itself|test\_object\_copy\_to\_itself|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_copy\_to\_itself\_with\_metadata|test\_object\_copy\_to\_itself\_with\_metadata|Y|N|Y||
|object\_create\_delete\_test.py|test\_object\_copy\_diff\_bucket|test\_object\_copy\_diff\_bucket|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_copy\_canned\_acl|test\_object\_copy\_canned\_acl|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_copy\_retaining\_metadata|test\_object\_copy\_retaining\_metadata|Y|N|Y||
|object\_create\_delete\_test.py|test\_object\_copy\_replacing\_metadata|test\_object\_copy\_replacing\_metadata|Y|N|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_get|test\_object\_raw\_get|Y|Y|N||
|object\_create\_delete\_test.py|test\_object\_raw\_get\_bucket\_gone|test\_object\_raw\_get\_bucket\_gone|Y|Y|N||
|object\_create\_delete\_test.py|test\_object\_delete\_key\_bucket\_gone|test\_object\_delete\_key\_bucket\_gone|Y|N|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_get\_object\_gone|test\_object\_raw\_get\_object\_gone|Y|Y|N||
|object\_create\_delete\_test.py|test\_object\_raw\_get\_bucket\_acl|test\_object\_raw\_get\_bucket\_acl|Y|Y|N||
|object\_create\_delete\_test.py|test\_object\_raw\_get\_object\_acl|test\_object\_raw\_get\_object\_acl|Y|N|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_authenticated|test\_object\_raw\_authenticated|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_response\_headers|test\_object\_raw\_response\_headers|Y|N|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_authenticated\_bucket\_acl|test\_object\_raw\_authenticated\_bucket\_acl|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_authenticated\_object\_acl|test\_object\_raw\_authenticated\_object\_acl|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_authenticated\_bucket\_gone|test\_object\_raw\_authenticated\_bucket\_gone|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_authenticated\_object\_gone|test\_object\_raw\_authenticated\_object\_gone|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_put|test\_object\_raw\_put|Y|N|N||
|object\_create\_delete\_test.py|test\_object\_raw\_put\_write\_access|test\_object\_raw\_put\_write\_access|Y|Y|N||
|object\_create\_delete\_test.py|test\_object\_raw\_put\_authenticated|test\_object\_raw\_put\_authenticated|Y|Y|Y||
|object\_create\_delete\_test.py|test\_object\_raw\_put\_authenticated\_expired|test\_object\_raw\_put\_authenticated\_expired|Y|N|Y||
|object\_list\_test.py|test\_object\_list\_empty|test\_bucket\_list\_empty|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_from\_distinct\_bucket|test\_bucket\_list\_distinct|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_many|test\_bucket\_list\_many|Y|N|N||
|object\_list\_test.py|test\_object\_list\_delimiter\_basic|test\_bucket\_list\_delimiter\_basic|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_delimiter\_alt|test\_bucket\_list\_delimiter\_alt|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_delimiter\_invalid|test\_bucket\_list\_delimiter\_unreadable<br>test\_bucket\_list\_delimiter\_empty<br>test\_bucket\_list\_delimiter\_not\_exist|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_delimiter\_none|test\_bucket\_list\_delimiter\_none|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_delimiter\_prefix|test\_bucket\_list\_delimiter\_prefix|Y|N|N||
|object\_list\_test.py|test\_object\_list\_prefix\_basic|test\_bucket\_list\_prefix\_basic|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_prefix\_alt|test\_bucket\_list\_prefix\_alt|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_special\_prefix|test\_bucket\_list\_prefix\_basic|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_prefix\_invalid|test\_bucket\_list\_prefix\_unreadable<br>test\_bucket\_list\_prefix\_not\_exist|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_prefix\_empty\_or\_none|test\_bucket\_list\_prefix\_empty<br>test\_bucket\_list\_prefix\_none|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_prefix\_delimiter\_basic|test\_bucket\_list\_prefix\_delimiter\_basic|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_prefix\_delimiter\_alt|test\_bucket\_list\_prefix\_delimiter\_alt|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_prefix\_delimiter\_prefix\_not\_exist|test\_bucket\_list\_prefix\_delimiter\_prefix\_not\_exist|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_prefix\_delimiter\_delimiter\_not\_exist|test\_bucket\_list\_prefix\_delimiter\_delimiter\_not\_exist|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_prefix\_delimiter\_prefix\_delimiter\_not\_exist|test\_bucket\_list\_prefix\_delimiter\_prefix\_delimiter\_not\_exist|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_maxkeys\_one|test\_bucket\_list\_maxkeys\_one|Y|N|N||
|object\_list\_test.py|test\_object\_list\_maxkeys\_zero|test\_bucket\_list\_maxkeys\_zero|Y|N|Y||
|object\_list\_test.py|test\_object\_list\_maxkeys\_none|test\_bucket\_list\_maxkeys\_none|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_maxkeys\_invalid|test\_bucket\_list\_maxkeys\_invalid<br>test\_bucket\_list\_maxkeys\_unreadable|Y|N|N||
|object\_list\_test.py|test\_object\_list\_marker\_invalid|test\_bucket\_list\_marker\_unreadable<br>test\_bucket\_list\_marker\_empty<br>test\_bucket\_list\_marker\_none|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_marker\_not\_in\_list|test\_bucket\_list\_marker\_not\_in\_list|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_marker\_after\_list|test\_bucket\_list\_marker\_after\_list|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_marker\_before\_list|test\_bucket\_list\_marker\_before\_list|Y|Y|Y||
|object\_list\_test.py|test\_object\_create\_special\_key\_names|test\_bucket\_create\_special\_key\_names|Y|Y|Y||
|object\_list\_test.py|test\_object\_list\_return\_data|test\_bucket\_list\_return\_data|Y|Y|N||
|object\_multipart\_test.py|test\_multipart\_upload\_empty|test\_multipart\_upload\_empty|Y|N|N||
|object\_multipart\_test.py|test\_multipart\_upload\_small|test\_multipart\_upload\_small|Y|N|Y||
|object\_multipart\_test.py|test\_multipart\_upload|test\_multipart\_upload|Y|N|Y||
|object\_multipart\_test.py|test\_multipart\_upload\_multiple\_sizes|test\_multipart\_upload\_multiple\_sizes|Y|N|Y||
|object\_multipart\_test.py|test\_multipart\_upload\_size\_too\_small|test\_multipart\_upload\_size\_too\_small|Y|N|N||
|object\_multipart\_test.py|test\_multipart\_upload\_contents|test\_multipart\_upload\_contents|Y|N|Y||
|object\_multipart\_test.py|test\_multipart\_upload\_overwrite\_existing\_object|test\_multipart\_upload\_overwrite\_existing\_object|Y|N|Y||
|object\_multipart\_test.py|test\_abort\_multipart\_upload|test\_abort\_multipart\_upload|Y|N|N||
|object\_multipart\_test.py|test\_abort\_multipart\_upload\_not\_found|test\_abort\_multipart\_upload\_not\_found|Y|N|Y||
|object\_multipart\_test.py|test\_list\_multipart\_upload|test\_list\_multipart\_upload|Y|N|N||
|object\_post\_test.py|test\_post\_object\_anonymous\_request|test\_post\_object\_anonymous\_request|Y|Y|N||
|object\_post\_test.py|test\_post\_object\_authenticated\_request|test\_post\_object\_authenticated\_request|Y|Y|N||
|object\_post\_test.py|test\_post\_object\_authenticated\_request\_bad\_access\_key|test\_post\_object\_authenticated\_request\_bad\_access\_key|Y|N|N||
|object\_post\_test.py|test\_post\_object\_set\_success\_code|test\_post\_object\_set\_success\_code|Y|Y|N||
|object\_post\_test.py|test\_post\_object\_set\_invalid\_success\_code|test\_post\_object\_set\_invalid\_success\_code|Y|N|N||
|object\_post\_test.py|test\_post\_object\_upload\_larger\_than\_chunk|test\_post\_object\_upload\_larger\_than\_chunk|Y|Y|N||
|object\_post\_test.py|test\_post\_object\_set\_key\_from\_filename|test\_post\_object\_set\_key\_from\_filename|Y|N|N||
|object\_post\_test.py|test\_post\_object\_ignored\_header|test\_post\_object\_ignored\_header|Y|Y|N||
|object\_post\_test.py|test\_post\_object\_case\_insensitive\_condition\_fields|test\_post\_object\_case\_insensitive\_condition\_fields|Y|Y|N||
|object\_post\_test.py|test\_post\_object\_escaped\_field\_values|test\_post\_object\_escaped\_field\_values|Y|Y|N||
|object\_post\_test.py|test\_post\_object\_success\_redirect\_action|test\_post\_object\_success\_redirect\_action|Y|N|N||
|object\_post\_test.py|test\_post\_object\_invalid\_signature|test\_post\_object\_invalid\_signature|Y|N|N||
|object\_post\_test.py|test\_post\_object\_invalid\_access\_key|test\_post\_object\_invalid\_access\_key|Y|N|N||
|object\_post\_test.py|test\_post\_object\_invalid\_date\_format|test\_post\_object\_invalid\_date\_format|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_no\_key\_specified|test\_post\_object\_no\_key\_specified|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_missing\_signature|test\_post\_object\_missing\_signature|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_missing\_policy\_condition|test\_post\_object\_missing\_policy\_condition|Y|N|N||
|object\_post\_test.py|test\_post\_object\_user\_specified\_header|test\_post\_object\_user\_specified\_header|Y|N|N||
|object\_post\_test.py|test\_post\_object\_request\_missing\_policy\_specified\_field|test\_post\_object\_request\_missing\_policy\_specified\_field|Y|N|N||
|object\_post\_test.py|test\_post\_object\_condition\_is\_case\_sensitive|test\_post\_object\_condition\_is\_case\_sensitive|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_expires\_is\_case\_sensitive|test\_post\_object\_expires\_is\_case\_sensitive|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_expired\_policy|test\_post\_object\_expired\_policy|Y|N|N||
|object\_post\_test.py|test\_post\_object\_invalid\_request\_field\_value|test\_post\_object\_invalid\_request\_field\_value|Y|N|N||
|object\_post\_test.py|test\_post\_object\_missing\_expires\_condition|test\_post\_object\_missing\_expires\_condition|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_missing\_conditions\_list|test\_post\_object\_missing\_conditions\_list|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_upload\_size\_limit\_exceeded|test\_post\_object\_upload\_size\_limit\_exceeded|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_missing\_content\_length\_argument|test\_post\_object\_missing\_content\_length\_argument|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_invalid\_content\_length\_argument|test\_post\_object\_invalid\_content\_length\_argument|Y|N|Y||
|object\_post\_test.py|test\_post\_object\_upload\_size\_below\_minimum|test\_post\_object\_upload\_size\_below\_minimum|Y|N|Y||