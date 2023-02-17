Class extends _BaseClass

property signatureMethod : cs:C1710.SignatureMethod

Class constructor($inParams : Object)
	
	Super:C1705()
	
	This:C1470._try()
	
	This:C1470.authorizeURLOAuthTokenParam:="oauth_token"  // TODO: let user change it by params
	This:C1470.authorizeURLConsumerKeyParam:="oauth_consumer_key"  // TODO: let user change it by params
	
/*
The Application ID that the registration portal assigned the app
*/
	This:C1470.clientId:=String:C10($inParams.clientId)
	// TODO: add consumerKey as alternative name
	
/*
The application secret that you created in the app registration portal for your app. Required for web apps.
*/
	
	This:C1470.clientSecret:=String:C10($inParams.clientSecret)
	// TODO: add consumerSecret as alternative name
	
/*
The redirect_uri of your app, where authentication responses can be sent and received by your app.
*/
	This:C1470.redirectURI:=String:C10($inParams.redirectURI)  // ie. the called the callback URI
	
	This:C1470.requestTokenURI:=String:C10($inParams.requestTokenURI)
	This:C1470.authenticateURI:=String:C10($inParams.authenticateURI)  // authorize... not authenticate...
	This:C1470.tokenURI:=String:C10($inParams.tokenURI)  //accesstoken... not token...
	
	If (Value type:C1509($inParams.scope)=Is collection:K8:32)
		This:C1470.scope:=$inParams.scope.join(" ")
	Else 
		This:C1470.scope:=String:C10($inParams.scope)
	End if 
	
	
	
	This:C1470.name:=String:C10($inParams.name)
	This:C1470._fillURIAccordingToName()
	
	This:C1470.signatureMethod:=(Length:C16(String:C10($inParams.signatureMethod))=0) ? cs:C1710.SignatureMethod.new() : cs:C1710.SignatureMethod.new(String:C10($inParams.signatureMethod))
	
	This:C1470._finally()
	
	
	// Alias of clientSecret
Function get consumerSecret : Text
	return This:C1470.clientSecret
	
	// Alias of clientId
Function get consumerKey : Text
	return This:C1470.clientId
	
Function _fillURIAccordingToName()
	
	Case of 
		: ((This:C1470.name=Null:C1517) || (Length:C16(String:C10(This:C1470.name))=0))
			
			// Ignore
			
		: (This:C1470.name="500px")
			
			This:C1470.requestTokenURI:="https://api.500px.com/v1/oauth/request_token"
			This:C1470.authenticateURI:="https://api.500px.com/v1/oauth/authorize"
			This:C1470.tokenURI:="https://api.500px.com/v1/oauth/access_token"
			
		: (This:C1470.name="twitter")
			
			This:C1470.requestTokenURI:="https://api.twitter.com/oauth/request_token"
			This:C1470.authenticateURI:="https://api.twitter.com/oauth/authorize"
			This:C1470.tokenURI:="https://api.twitter.com/oauth/access_token"
			
		: (This:C1470.name="flickr")
			
			This:C1470.requestTokenURI:="https://www.flickr.com/services/oauth/request_token"
			This:C1470.authenticateURI:="https://www.flickr.com/services/oauth/authorize"
			This:C1470.tokenURI:="https://www.flickr.com/services/oauth/access_token"
			
		: (This:C1470.name="smugmug")
			
			This:C1470.requestTokenURI:="http://api.smugmug.com/services/oauth/getRequestToken.mg"
			This:C1470.authenticateURI:="http://api.smugmug.com/services/oauth/authorize.mg"
			This:C1470.tokenURI:="http://api.smugmug.com/services/oauth/getAccessToken.mg"
			
		: (This:C1470.name="bitbucket")
			
			This:C1470.requestTokenURI:="https://bitbucket.org/api/1.0/oauth/request_token"
			This:C1470.authenticateURI:="https://bitbucket.org/api/1.0/oauth/authenticate"
			This:C1470.tokenURI:="https://bitbucket.org/api/1.0/oauth/access_token"
			
		: (This:C1470.name="intuit")
			
			This:C1470.requestTokenURI:="https://oauth.intuit.com/oauth/v1/get_request_token"
			This:C1470.authenticateURI:="https://appcenter.intuit.com/Connect/Begin"
			This:C1470.tokenURI:="https://oauth.intuit.com/oauth/v1/get_access_token"
			
		: (This:C1470.name="zaim")
			
			This:C1470.requestTokenURI:="https://api.zaim.net/v2/auth/request"
			This:C1470.authenticateURI:="https://auth.zaim.net/users/auth"
			This:C1470.tokenURI:="https://api.zaim.net/v2/auth/access"
			
		: (This:C1470.name="tumblr")
			
			This:C1470.requestTokenURI:="https://www.tumblr.com/oauth/request_token"
			This:C1470.authenticateURI:="https://www.tumblr.com/oauth/authorize"
			This:C1470.tokenURI:="https://www.tumblr.com/oauth/access_token"
			
		: (This:C1470.name="twihatenatter")
			
			This:C1470.requestTokenURI:="https://www.hatena.com/oauth/initiate"
			This:C1470.authenticateURI:="https://www.hatena.ne.jp/oauth/authorize"
			This:C1470.tokenURI:="https://www.hatena.com/oauth/token"
			
		: (This:C1470.name="trello")
			
			This:C1470.requestTokenURI:="https://trello.com/1/OAuthGetRequestToken"
			This:C1470.authenticateURI:="https://trello.com/1/OAuthAuthorizeToken"
			This:C1470.tokenURI:="https://trello.com/1/OAuthGetAccessToken"
			
		: (This:C1470.name="goodreads")
			
			This:C1470.requestTokenURI:="https://www.goodreads.com/oauth/request_token"
			This:C1470.authenticateURI:="https://www.goodreads.com/oauth/authorize?mobile=1"
			This:C1470.tokenURI:="https://www.goodreads.com/oauth/access_token"
			
		: (This:C1470.name="wordpress")
			If (This:C1470.wordpressURI=Null:C1517)
				This:C1470._throwError(2; New object:C1471("attribute"; "wordpressURI"))
			End if 
			This:C1470.requestTokenURI:=This:C1470.wordpressURI+"/oauth1/request"
			This:C1470.authenticateURI:=This:C1470.wordpressURI+"/oauth1/authorize"
			This:C1470.tokenURI:=This:C1470.wordpressURI+"oauth1/access"
			
		Else 
			// TODO: throw for insvalid name?
			This:C1470._throwError(3; New object:C1471("attribute"; "name"))
	End case 
	
Function _encodeToken($token : Text) : Text
	If (Bool:C1537(This:C1470.useRFC3986ToEncodeToken))
		return This:C1470._urlEncoded($token)
	Else 
		return This:C1470._urlQueryEncoded($token)
	End if 
	
Function _formEncoded($object : Object)->$text : Text
	$text:=OB Entries:C1720($object).map(Formula:C1597($1.value.key+"="+$1.value.value)).join("&")
	
Function _authorizationHeader($opt : Object; $url : Text; $parameters : Object)->$header : Text
	
	$header:="OAuth "
	
	var $headerComponents : Collection
	$headerComponents:=New collection:C1472
	
	var $authorizationParameters : Object
	$authorizationParameters:=This:C1470._authorizationParametersWithSignature($opt.method; $opt.body; $url; $parameters)
	
	var $parameterComponents : Collection
	$parameterComponents:=Split string:C1554(This:C1470._urlEncodedQuery($authorizationParameters); "&")
	$parameterComponents.sort(This:C1470._sortP)  // XXX maybe This._sortP
	
	var $component : Text
	var $subcomponent : Collection
	For each ($component; $parameterComponents)
		$subcomponent:=Split string:C1554($component; "=")
		If ($subcomponent.length=2)
			$headerComponents.push($subcomponent[0]+"="+"\""+$subcomponent[1]+"\"")
		End if 
	End for each 
	
	$header+=$headerComponents.join(", ")
	
	
Function _getTimeStamp($date : Date; $time : Time)->$epoc : Integer
	// copyed from forum, maybe could do better...
	var $vt_timestampUtc : Text
	$vt_timestampUtc:=String:C10($date; ISO date GMT:K1:10; $time)
	$vt_timestampUtc:=Substring:C12($vt_timestampUtc; 1; 19)  //remove the"Z"
	
	C_DATE:C307($vd_dateUtc)
	C_TIME:C306($vh_timeUtc)
	XML DECODE:C1091($vt_timestampUtc; $vd_dateUtc)
	XML DECODE:C1091($vt_timestampUtc; $vh_timeUtc)
	
	$epoc:=(($vd_dateUtc-!1970-01-01!)*86400)+$vh_timeUtc
	
Function _timeIntervalSince1970()->$timeString : Text
	$timeString:=String:C10(This:C1470._getTimeStamp(Current date:C33; 0))
	
Function _nonce()->$nonce : Text
	$nonce:=Substring:C12(Generate UUID:C1066; 1; 8)
	
Function _authorizationParametersWithSignature($method; $body; $url; $parameters : Object)->$authorizationParameters : Object
	var $timestamp; $nonce : Text
	$timestamp:=This:C1470._timeIntervalSince1970()
	$nonce:=This:C1470._nonce()
	
	var $authorizationParameters : Object
	$authorizationParameters:=This:C1470._authorizationParameters($body; $timestamp; $nonce)
	
	var $entries : Object
	For each ($entries; OB Entries:C1720($parameters))
		If (Position:C15("oauth_"; $entries.key)=1)
			$authorizationParameters[$entries.key]:=$entries.value
		Else 
			// XXX: maybe check if not already defined in $authorizationParameters to not override it?
			$authorizationParameters[$entries.key]:=$entries.value
		End if 
	End for each 
	
	
	$authorizationParameters["oauth_signature"]:=This:C1470._signature($method; $url; $authorizationParameters)
	
	
Function _authorizationParameters($body : Variant; $timestamp : Text; $nonce : Text)->$authorizationParameters : Object
	$authorizationParameters:=New object:C1471
	$authorizationParameters["oauth_version"]:="1.0"
	$authorizationParameters["oauth_signature_method"]:=This:C1470.signatureMethod.rawValue
	$authorizationParameters["oauth_consumer_key"]:=This:C1470.consumerKey
	$authorizationParameters["oauth_timestamp"]:=$timestamp
	$authorizationParameters["oauth_nonce"]:=$nonce
	
	var $hash : Text
	$hash:=This:C1470.signatureMethod.hash($body)
	If (($hash#Null:C1517) && (Length:C16($hash)>0))
		$authorizationParameters["oauth_body_hash"]:=$hash
	End if 
	
	If (Length:C16(String:C10(This:C1470.oauthToken))>0)
		$authorizationParameters["oauth_token"]:=This:C1470.oauthToken
	End if 
	
Function _sortP($obj : Object)
	var $p0; $p1 : Collection
	$p0:=Split string:C1554($obj.value; "=")
	$p1:=Split string:C1554($obj.value2; "=")
	If ($p0[0]=$p1[0])
		$obj.result:=$p0[1]<$p1[1]
	Else 
		$obj.result:=$p0[0]<$p1[0]
	End if 
	
Function _signature($method : Text; $url : Text; $parameters : Object)->$sign : Text
	
	var $encodedTokenSecret; $encodedConsumerSecret : Text
	$encodedTokenSecret:=This:C1470._urlEncoded(This:C1470.oauthTokenSecret)
	$encodedConsumerSecret:=This:C1470._urlEncoded(This:C1470.consumerSecret)
	
	var $signingKey : Text
	$signingKey:=$encodedConsumerSecret+"&"+$encodedTokenSecret
	
	If (This:C1470.signatureMethod.name="PLAINTEXT")
		
		$sign:=$signingKey
		return 
	End if 
	
	var $parameterComponents : Collection
	$parameterComponents:=Split string:C1554(This:C1470._urlEncodedQuery($parameters); "&")
	$parameterComponents.sort(This:C1470._sortP)
	
	var $parameterString; $encodedParameterString : Text
	$parameterString:=$parameterComponents.join("&")
	$encodedParameterString:=This:C1470._urlEncoded($parameterString)
	
	var $encodedURL : Text
	$encodedURL:=This:C1470._urlEncoded($url)
	
	var $signatureBaseString : Text
	$signatureBaseString:=$method+"&"+$encodedURL+"&"+$encodedParameterString
	
	$sign:=This:C1470.signatureMethod.sign($signingKey; $signatureBaseString)
	
	
Function _data($text : Text)->$data : Blob
	TEXT TO BLOB:C554($text; $data)
	
Function _base64EncodedString($data : Blob)->$encoded : Text
	BASE64 ENCODE:C895($data; $encoded)
	
	// 1- post requestTokenURI
Function _postOAuthRequestToken()->$result : Object
	
	var $parameters : Object
	$parameters:=New object:C1471
	$parameters["oauth_callback"]:=This:C1470.redirectURI
	$parameters["oauth_consumer_key"]:=This:C1470.clientID
	$parameters["oauth_consumer_secret"]:=This:C1470.clientSecret
	
	var $options : Object
	$options:=New object:C1471
	$options.headers:=New object:C1471("Content-Type"; "application/x-www-form-urlencoded")
	// TODO: Add custom headers from client (needed sometimes)
	$options.method:=HTTP POST method:K71:2
	$options.body:=This:C1470._formEncoded($parameters)
	$options.dataType:="text"
	
	var $signatureURL : Text
	var $signatureParameters : Object
	$signatureParameters:=New object:C1471
	$signatureParameters:=$parameters  // TODO: or any parameters find in This.requestTokenURI, requestTokenURI must have all query parameters removed to create $signatureURL
	$signatureURL:=This:C1470.requestTokenURI
	ASSERT:C1129(Position:C15("?"; $signatureURL)=0; "Request token URI with query parameters is not supported yet")
	
	// TODO: Sign headers
	$options.headers["Authorization"]:=This:C1470._authorizationHeader($options; $signatureURL; $signatureParameters)
	
	var $savedMethod : Text
	$savedMethod:=Method called on error:C704
	ON ERR CALL:C155("_ErrorHandler")
	var $request : 4D:C1709.HTTPRequest
	$request:=4D:C1709.HTTPRequest.new(This:C1470.requestTokenURI; $options)
	$request.wait(30)
	ON ERR CALL:C155($savedMethod)
	
	var $status : Integer
	var $response : Text
	$status:=$request["response"]["status"]
	$response:=$request["response"]["body"]
	
	// ON http receive
	
	If ($status=200)
		
		If (Length:C16($response)>0)
			
			//$result:=cs.OAuth1Token.new()
			//$result._loadFromResponse($response)
			
			$responseParameters:=This:C1470._parametersFromQueryString($response.parametersFromQueryString)
			// important one are
			This:C1470.oauthToken:=$responseParameters["oauth_token"] || $responseParameters["token"]
			This:C1470.oauthTokenSecret:=$responseParameters["oauth_token_secret"]
			// could be response if already connected
			
			This:C1470._authorize()
			
		Else 
			
			var $licenseAvailable : Boolean
			If (Application type:C494=4D Remote mode:K5:5)
				$licenseAvailable:=Is license available:C714(4D Client Web license:K44:6)
			Else 
				$licenseAvailable:=(Is license available:C714(4D Web license:K44:3) | Is license available:C714(4D Web local license:K44:14) | Is license available:C714(4D Web one connection license:K44:15))
			End if 
			If ($licenseAvailable)
				This:C1470._throwError(4)  // Timeout error
			Else 
				This:C1470._throwError(11)  // License error
			End if 
			
		End if 
		
	Else 
		
		var $explanation : Text
		$explanation:=$request["response"]["statusText"]
		
		var $error : Object
		
		$error:=JSON Parse:C1218($response)
		If ($error#Null:C1517)
			var $errorCode : Integer
			var $message : Text
			
			If (Num:C11($error.error_codes.length)>0)
				$errorCode:=Num:C11($error.error_codes[0])
			End if 
			$message:=String:C10($error.error_description)
			
			This:C1470._throwError(8; New object:C1471("status"; $status; "explanation"; $explanation; "message"; $message))
		Else 
			
			This:C1470._throwError(5; New object:C1471("received"; $status; "expected"; 200))
		End if 
		
	End if 
	
	// 2: post authorize
Function _authorize
	// or:
	$token:=This:C1470._encodeToken(This:C1470.oauthToken)  // but encoded
	$urlString:=This:C1470.authenticateURI+(This:C1470.authenticateURI.contains("?") ? "&" : "?")
	$urlString+=This:C1470.authorizeURLOAuthTokenParam+"="+$token
	If (Bool:C1537(This:C1470.addConsumerKeyToAuthorizeURL))  // optional
		$urlString+="&"+This:C1470.authorizeURLConsumerKeyParam+"="+This:C1470.clientID
	End if 
	If (Bool:C1537(This:C1470.addCallbackURLToAuthorizeURL))  // optional
		$urlString+="&oauth_callback="+This:C1470.redirectURI
	End if 
	
	// TODO: open browser or any way to validate
	This:C1470.authorizeURLHandler.handle($urlString)
	// -> must launch > waitRedirect
	
	
	// 2bis: receive authorize and call next step
Function waitRedirect
	// Then wait redirection? and get it
	var $responseParameters : Object
	$responseParameters:=$queryString.parametersFromQueryString
	$responseParameters:=$fragment.parametersFromQueryString
	//$responseParameters["oauth_token"] || $responseParameters["token"]
	If ($responseParameters["oauth_token"]=Null:C1517)
		// TODO: throw
		
	Else 
		This:C1470.oauthToken=$responseParameters["oauth_token"].safeStringByRemovingPercentEncoding
		If ($responseParameters["oauth_verifier"]#Null:C1517)
			This:C1470.oauthVerifier=$responseParameters["oauth_verifier"].safeStringByRemovingPercentEncoding
		Else 
			If (Bool:C1537(This:C1470.allowMissingOAuthVerifier))
				// its ok
			Else 
				// TODO: throw missing oauth verifier
			End if 
		End if 
		
		This:C1470._postOAuthAccessTokenWithRequestToken()
		
	End if 
	
	// 3- get finally token
Function _postOAuthAccessTokenWithRequestToken()
	var $parameters : Object
	$parameters:=New object:C1471
	$parameters["oauth_token"]=This:C1470.oauthToken
	$parameters["oauth_verifier"]=This:C1470.oauthVerifier
	
	// HTTP POST This.tokenURI
	var $responseParameters : Text
	$responseParameters:=$response.parametersFromQueryString
	This:C1470.oauthToken:=$responseParameters["oauth_token"].safeStringByRemovingPercentEncoding
	If ($responseParameters["oauth_token_secret"]#Null:C1517)
		This:C1470.oauthTokenSecret:=$responseParameters["oauth_token_secret"].safeStringByRemovingPercentEncoding
	End if 
	
	// on completion it's finish
	
	// MARK: - text function
	// TODO: url encode things
Function _urlEncoded($toEncode)->$encoded : Text
	
	// COPYED FROM https://github.com/miyako/4d-tips-encode-uri
	C_LONGINT:C283($i)
	C_BOOLEAN:C305($shouldEncode)
	C_BLOB:C604($data)
	
	C_TEXT:C284($char; $hex)
	C_LONGINT:C283($code; $j)
	
	For ($i; 1; Length:C16($toEncode))
		
		$char:=Substring:C12($toEncode; $i; 1)
		$code:=Character code:C91($char)
		
		$shouldEncode:=False:C215
		
		Case of 
			: ($code=45)
				// -
			: ($code=46)
				// .
			: ($code>47) & ($code<58)
				// 0 1 2 3 4 5 6 7 8 9
			: ($code>64) & ($code<91)
				// A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
			: ($code=95)
				// _
			: ($code>96) & ($code<123)
				// a b c d e f g h i j k l m n o p q r s t u v w x y z
			: ($code=126)
				// ~
			Else 
				$shouldEncode:=True:C214
		End case 
		
		If ($shouldEncode)
			CONVERT FROM TEXT:C1011($char; "utf-8"; $data)
			For ($j; 0; BLOB size:C605($data)-1)
				$hex:=String:C10($data{$j}; "&x")
				$encoded:=$encoded+"%"+Substring:C12($hex; Length:C16($hex)-1)
			End for 
		Else 
			If ($code=32)
				$encoded:=$encoded+"+"
			Else 
				$encoded:=$encoded+$char
			End if 
		End if 
		
	End for 
	
	
	$encoded:=$toEncode
	
Function _urlQueryEncoded($toEncode : Text)->$encoded : Text
	
	// COPYED FROM https://github.com/miyako/4d-tips-encode-uri
	C_LONGINT:C283($i)
	C_BOOLEAN:C305($shouldEncode)
	C_BLOB:C604($data)
	
	C_TEXT:C284($char; $hex)
	C_LONGINT:C283($code; $j)
	
	For ($i; 1; Length:C16($toEncode))
		
		$char:=Substring:C12($toEncode; $i; 1)
		$code:=Character code:C91($char)
		
		$shouldEncode:=False:C215
		
		Case of 
			: ($code=32)
				// <space>
			: ($code=45)
				// -
			: ($code=46)
				// .
			: ($code>47) & ($code<58)
				// 0 1 2 3 4 5 6 7 8 9
			: ($code>64) & ($code<91)
				// A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
			: ($code=95)
				// _
			: ($code>96) & ($code<123)
				// a b c d e f g h i j k l m n o p q r s t u v w x y z
			: ($code=126)
				// ~
			Else 
				$shouldEncode:=True:C214
		End case 
		
		If ($shouldEncode)
			CONVERT FROM TEXT:C1011($char; "utf-8"; $data)
			For ($j; 0; BLOB size:C605($data)-1)
				$hex:=String:C10($data{$j}; "&x")
				$encoded:=$encoded+"%"+Substring:C12($hex; Length:C16($hex)-1)
			End for 
		Else 
			If ($code=32)
				$encoded:=$encoded+"+"
			Else 
				$encoded:=$encoded+$char
			End if 
		End if 
		
	End for 
	
Function _urlEncodedQuery($object : Object)->$encoded : Text
	$encoded:=OB Entries:C1720($object).map(Formula:C1597($2._urlQueryEncoded($1.value.key)+"="+$2._urlQueryEncoded($1.value.value)); This:C1470)\
		.join("&")
	
	
	// Mark: - [Public]
	// ----------------------------------------------------
	
	
Function getToken()->$result : Object
	
	$result:=This:C1470._postOAuthRequestToken()
	