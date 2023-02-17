//%attributes = {}


var $provider : cs:C1710.OAuth1Provider
var $parameters : Object

var $secretFile : 4D:C1709.Folder
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
