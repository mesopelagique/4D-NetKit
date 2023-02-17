//%attributes = {}


var $provider : cs:C1710.OAuth1Provider
var $parameters : Object

var $secretFile : 4D:C1709.File
$secretFile:=Folder:C1567(fk desktop folder:K87:19).file("oauth.json")  /// XXX could add in resources with a gitignore maybe

var $secret : Object
$secret:=JSON Parse:C1218($secretFile.getText())

$parameters:=New object:C1471
$parameters.name:="twitter"
$parameters.clientId:=$secret["twitter"]["clientId"]
$parameters.clientSecret:=$secret["twitter"]["clientSecret"]
$parameters.redirectURI:="http://localhost/oauth1/"

$provider:=New OAuth1 provider($parameters)

var $token : Object
$token:=$provider.getToken()

var $URL : Text
var $options : Object
var $request : 4D:C1709.HTTPRequest

$URL:="https://api.twitter.com/1.1/statuses/mentions_timeline.json"
$options:=New object:C1471
$options.method:=HTTP GET method:K71:1

If ($options.headers=Null:C1517)
	$options.headers:=New object:C1471
End if 
$options.headers["Authorization"]:=$token._authorizationHeader($options; $URL; New object:C1471)

$request:=4D:C1709.HTTPRequest.new($URL; $options)

$request.wait(30)

var $status : Integer
$status:=$request["response"]["status"]

If (Asserted:C1132($status=200; "Not receive data from provider"))
	
	var $timeline : Variant
	$timeline:=$request["response"]["body"]
	
End if 