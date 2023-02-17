//%attributes = {}
var $testCases : Collection
var $testCase : Object
var $signatureMethod : cs:C1710.SignatureMethod
$signatureMethod:=cs:C1710.SignatureMethod.new("HMAC-SHA1")

var $result : Text


// MARK: - hash sha1 test
$testCases:=New collection:C1472(New object:C1471("value"; "Hello World!"; "result"; "Lve95gjOVATpfV8EL5X4nxwjKHE="))

For each ($testCase; $testCases)
	
	$result:=$signatureMethod.hash($testCase.value)
	ASSERT:C1129($result=$testCase.result; "Not correct hash for "+$testCase.value+" : result="+$result+" instead of "+$testCase.result)
	
End for each 

// MARK: - sign hmac-sha1 test
$testCases:=New collection:C1472(\
New object:C1471("key"; "abcedfg123456789"; "message"; "simon says"; "result"; "vyeIZc3+tF6F3i95IEV+AJCWBYQ="); \
New object:C1471("key"; "kd94hf93k423kf44&pfkkdhi9sl3r4s00"; \
"message"; "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_vers"+"ion%3D1.0%26size%3Doriginal&kd94hf93k423kf44&pfkkdhi9sl3r4s00"; \
"result"; "Gcg/323lvAsQ707p+y41y14qWfY="))

For each ($testCase; $testCases)
	
	$result:=$signatureMethod.sign($testCase.key; $testCase.message)
	
	ASSERT:C1129($result=$testCase.result; "Not correct sign for "+$testCase.key+" : result="+$result+" instead of "+$testCase.result)
	
End for each 

// MARK: - test signature

$testCases:=New collection:C1472(\
New object:C1471("name"; "testGET"; "url"; "http://photos.example.net/photos"; \
"clientID"; "dpf43f3p2l4k3l03"; "clientSecret"; "kd94hf93k423kf44"; "token"; "nnch734d00sl2jdk"; "tokenSecret"; "pfkkdhi9sl3r4s00"; \
"parameters"; New collection:C1472("file"; "vacation.jpg"; "size"; "original"); \
"nonce"; "kllo9940pd9333jh"; "timestamp"; "1191242096"; "method"; "GET"; "result"; "tR3+Ty81lMeYAr/Fid0kMTYa/WM="); \
New object:C1471("name"; "testPOST"; "url"; "http://photos.example.net/photos"; \
"clientID"; "abcd"; "clientSecret"; "efgh"; "token"; "ijkl"; "tokenSecret"; "mnop"; \
"parameters"; New collection:C1472("name"; "value"); \
"nonce"; "rkNG5bfzqFw"; "timestamp"; "1451152366"; "method"; "POST"; "result"; "6qB7WBgezEpKhfr2Bpl+HfcS4SA="); \
New object:C1471("name"; "testSpaceURL"; "url"; "photos.example.net/ph%20otos"; \
"clientID"; "abcd"; "clientSecret"; "efgh"; "token"; "ijkl"; "tokenSecret"; "mnop"; \
"parameters"; New collection:C1472("name"; "value"); \
"nonce"; "rkNG5bfzqFw"; "timestamp"; "1451152366"; "method"; "GET"; "result"; "g2HpPCyQIVxLC3NNVn2x9oeUtyg="); \
New object:C1471("name"; "testSamePrefix"; "url"; "photos.example.net/photos"; \
"clientID"; "dpf43f3p2l4k3l03"; "clientSecret"; "kd94hf93k423kf44"; "token"; "nnch734d00sl2jdk"; "tokenSecret"; "pfkkdhi9sl3r4s00"; \
"parameters"; New collection:C1472("file_1"; "vacation.jpg"; "file_10"; "original"); \
"nonce"; "kllo9940pd9333jh"; "timestamp"; "1191242096"; "method"; "GET"; "result"; "2qG5S5iX/g/6NIKutdcSYACUHsg="))

var $provider : cs:C1710.OAuth1Provider
var $authorizationParameters : Object
var $key : Text
For each ($testCase; $testCases)
	
	$provider:=New OAuth1 provider($testCase)  // TODO: create only a OAuth1Token to test sign
	$provider.oauthToken:=$testCase.token
	$provider.oauthTokenSecret:=$testCase.tokenSecret
	
	$authorizationParameters:=$provider._authorizationParameters(Null:C1517; $testCase.timestamp; $testCase.nonce)
	For each ($key; $testCase.parameters)
		$authorizationParameters[$key]:=$testCase.parameters[$key]
	End for each 
	
	$result:=$provider._signature($testCase.method; $testCase.url; $authorizationParameters)
	
	ASSERT:C1129($result=$testCase.result; "Not correct sign for url "+$testCase.name+" : result="+$result+" instead of "+$testCase.result)
	
End for each 