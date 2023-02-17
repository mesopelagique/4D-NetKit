Class constructor($name : Text)
	If (Count parameters:C259>0)
		This:C1470.name:=$name
		ASSERT:C1129(New collection:C1472("HMAC-SHA1"/*; "RSA-SHA1"; "PLAINTEXT"*/).indexOf($name)>=0; "Unknown signature method "+$name)
	Else 
		This:C1470.name:="HMAC-SHA1"  //"RSA-SHA1", "PLAINTEXT"
	End if 
	
Function get algoName : Text
	Case of 
		: (This:C1470.name="HMAC-SHA1")  // https://www.rfc-editor.org/rfc/rfc5849#section-3.4.2
			return "SHA1"
		: (This:C1470.name="RSA-SHA1")  // https://www.rfc-editor.org/rfc/rfc5849#section-3.4.3
			return "SHA1"
		: (This:C1470.name="PLAINTEXT")  // https://www.rfc-editor.org/rfc/rfc5849#section-3.4.4
			return ""
		Else 
			ASSERT:C1129(False:C215; "unknown signature method "+String:C10(This:C1470.name))
	End case 
	
Function hash($data : Variant)->$result : Text
	var $dataBlob : Blob
	Case of 
			
			//________________________________________
		: (Value type:C1509($data)=Is text:K8:3)
			
			TEXT TO BLOB:C554($data; $dataBlob; UTF8 text without length:K22:17)
			
			//________________________________________
		: (Value type:C1509($data)=Is BLOB:K8:12)
			
			$dataBlob:=$data
			
		Else 
			
			ASSERT:C1129(False:C215; "Not correct data type to hash "+String:C10(Value type:C1509($data)))
			$result:=""
			return ""
			
			//________________________________________
	End case 
	
	var $algoName : Text
	$algoName:=This:C1470.algoName
	
	var $algo : Integer
	
	Case of 
			
			//________________________________________
		: ($algoName="SHA1")
			
			$algo:=SHA1 digest:K66:2
			
			//________________________________________
		Else 
			
			ASSERT:C1129(False:C215; "bad hash algo "+$algoName)
			
			//________________________________________
	End case 
	
	$result:=Generate digest:C1147($dataBlob; $algo; *)  // XXX check if url encoded or not
	var $b : Blob
	BASE64 DECODE:C896($result; $b; *)
	BASE64 ENCODE:C895($b; $result)
	
	
Function sign($key : Variant; $message : Variant)->$signed : Text
	If (Length:C16(This:C1470.algoName)=0)
		ASSERT:C1129(False:C215; "no also to sign")  // for instance plain text
	Else 
		$signed:=This:C1470._HMAC(This:C1470.algoName; $key; $message)
	End if 
	
/**
$key : key to sign
$message : to sign with$key
$method : 'SHA1' 'SHA256' or 'SHA512'
*/
Function _HMAC($algoName : Text; $key : Variant; $message : Variant)->$result : Text
	
	// accept blob or text for key and message, so convert it
	var $keyBlob; $messageBlob : Blob
	
	Case of 
			
			//________________________________________
		: (Value type:C1509($key)=Is text:K8:3)
			
			TEXT TO BLOB:C554($key; $keyBlob; UTF8 text without length:K22:17)
			
			//________________________________________
		: (Value type:C1509($key)=Is BLOB:K8:12)
			
			$keyBlob:=$key
			
		Else 
			
			ASSERT:C1129(False:C215; "Not correct key type "+String:C10(Value type:C1509($key)))
			
			//________________________________________
	End case 
	
	Case of 
			
			//________________________________________
		: (Value type:C1509($message)=Is text:K8:3)
			
			TEXT TO BLOB:C554($message; $messageBlob; UTF8 text without length:K22:17)
			
			//________________________________________
		: (Value type:C1509($message)=Is BLOB:K8:12)
			
			$messageBlob:=$message
			
		Else 
			
			ASSERT:C1129(False:C215; "Not correct message type "+String:C10(Value type:C1509($key)))
			
			//________________________________________
	End case 
	
	var $outerKey; $innerKey; $b : Blob
	var $blockSize; $i; $byte; $algo : Integer
	
	Case of 
			
			//________________________________________
		: ($algoName="SHA1")
			
			$algo:=SHA1 digest:K66:2
			$blockSize:=64
			
			//________________________________________
		: ($algoName="SHA256")
			
			$algo:=SHA256 digest:K66:4
			$blockSize:=64
			
			//________________________________________
		: ($algoName="SHA512")
			
			$algo:=SHA512 digest:K66:5
			$blockSize:=128
			
			//________________________________________
		Else 
			
			ASSERT:C1129(False:C215; "bad hash algo")
			
			//________________________________________
	End case 
	
	If (BLOB size:C605($keyBlob)>$blockSize)
		
		BASE64 DECODE:C896(Generate digest:C1147($keyBlob; $algo; *); $keyBlob; *)
		
	End if 
	
	If (BLOB size:C605($keyBlob)<$blockSize)
		
		SET BLOB SIZE:C606($keyBlob; $blockSize; 0)
		
	End if 
	
	ASSERT:C1129(BLOB size:C605($keyBlob)=$blockSize)
	
	SET BLOB SIZE:C606($outerKey; $blockSize)
	SET BLOB SIZE:C606($innerKey; $blockSize)
	
	//%r-
	For ($i; 0; $blockSize-1; 1)
		
		$byte:=$keyBlob{$i}
		$outerKey{$i}:=$byte ^| 0x005C
		$innerKey{$i}:=$byte ^| 0x0036
		
	End for 
	
	//%r+
	
	// append $message to $innerKey
	COPY BLOB:C558($messageBlob; $innerKey; 0; $blockSize; BLOB size:C605($messageBlob))
	BASE64 DECODE:C896(Generate digest:C1147($innerKey; $algo; *); $b; *)
	
	// append hash(innerKey + message) to outerKey
	COPY BLOB:C558($b; $outerKey; 0; $blockSize; BLOB size:C605($b))
	
/*$result:=Generate digest($outerKey; $algo)
TEXT TO BLOB($result; $b)
BASE64 ENCODE($b; $result)*/
	
	$result:=Generate digest:C1147($outerKey; $algo; *)
	var $b : Blob
	BASE64 DECODE:C896($result; $b; *)
	BASE64 ENCODE:C895($b; $result)