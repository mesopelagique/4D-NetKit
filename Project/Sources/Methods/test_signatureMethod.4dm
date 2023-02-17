//%attributes = {}


var $testCases; $testCase : Collection

var $signatureMethod : cs:C1710.SignatureMethod
$signatureMethod:=cs:C1710.SignatureMethod.new("HMAC-SHA1")


// MARK: - hash sha1 test
$testCases:=New collection:C1472(New collection:C1472("Hello World!"; "Lve95gjOVATpfV8EL5X4nxwjKHE="))

For each ($testCase; $testCases)
	
	$result:=$signatureMethod.hash($testCase[0])
	ASSERT:C1129($result=$testCase[1]; "Not correct hash for "+$testCase[0]+" : result="+$result+" instead of "+$testCase[1])
	
	// FIXME: missing padding = ?
	
End for each 

$testCases:=New collection:C1472(\
New collection:C1472("abcedfg123456789"; "simon says"; "vyeIZc3+tF6F3i95IEV+AJCWBYQ="); \
New collection:C1472("kd94hf93k423kf44&pfkkdhi9sl3r4s00"; \
"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_vers"+"ion%3D1.0%26size%3Doriginal&kd94hf93k423kf44&pfkkdhi9sl3r4s00"; \
"Gcg/323lvAsQ707p+y41y14qWfY="))


// MARK: - sign hmac-sha1 test
var $result : Text
For each ($testCase; $testCases)
	
	$result:=$signatureMethod.sign($testCase[0]; $testCase[1])
	
	ASSERT:C1129($result=$testCase[2]; "Not correct sign for "+$testCase[0]+" : result="+$result+" instead of "+$testCase[2])
	
	// FIXME: missing padding = ? and wrong encoding?
	
End for each 