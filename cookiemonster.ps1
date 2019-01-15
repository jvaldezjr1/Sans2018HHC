function e_d_file($key, $File, $enc_it) {
		[byte[]]$key = $key;
		$Suffix = "`.wannacookie";
		[System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography');
		[System.Int32]$KeySize = $key.Length*8;
		$AESP = New-Object 'System.Security.Cryptography.AesManaged';
		$AESP.Mode = [System.Security.Cryptography.CipherMode]::CBC;
		$AESP.BlockSize = 128;
		$AESP.KeySize = $KeySize;
		$AESP.Key = $key;
		$FileSR = New-Object System.IO.FileStream($File, [System.IO.FileMode]::Open);
		if ($enc_it) {$DestFile = $File + $Suffix} else {$DestFile = ($File -replace $Suffix)};
		$FileSW = New-Object System.IO.FileStream($DestFile, [System.IO.FileMode]::Create);
		if ($enc_it) {
			$AESP.GenerateIV();
			$FileSW.Write([System.BitConverter]::GetBytes($AESP.IV.Length), 0, 4);
			$FileSW.Write($AESP.IV, 0, $AESP.IV.Length);
			$Transform = $AESP.CreateEncryptor()
		}
		else {
			[Byte[]]$LenIV = New-Object Byte[] 4;
			$FileSR.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null;
			$FileSR.Read($LenIV,  0, 3) | Out-Null;
			[Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0);
			[Byte[]]$IV = New-Object Byte[] $LIV;
			$FileSR.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null;
			$FileSR.Read($IV, 0, $LIV) | Out-Null;
			$AESP.IV = $IV;
			$Transform = $AESP.CreateDecryptor()
		};
	$CryptoS = New-Object System.Security.Cryptography.CryptoStream($FileSW, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write);
	[Int]$Count = 0;
	[Int]$BlockSzBts = $AESP.BlockSize / 8;
	[Byte[]]$Data = New-Object Byte[] $BlockSzBts;
	Do {
		$Count = $FileSR.Read($Data, 0, $BlockSzBts);
		$CryptoS.Write($Data, 0, $Count)
	} While ($Count -gt 0);
	$CryptoS.FlushFinalBlock();
	$CryptoS.Close();
	$FileSR.Close();
	$FileSW.Close();
	}
# Hex 2 Bytes
function H2B {
	param($HX);
	$HX = $HX -split '(..)' | ? { $_ };
	ForEach ($value in $HX) {
		[Convert]::ToInt32($value,16)
	}
};

# Bytes to Hex
function B2H {
    param($DEC);
	$tmp = '';
	ForEach ($value in $DEC) {
        $a = "{0:x}" -f [Int]$value;
	    if ($a.length -eq 1) {$tmp += '0' + $a} 
        else {$tmp += $a}
    };
	return $tmp
};

# public key encryption (bk, pk- aka server.crt)
function p_k_e($key_bytes, [byte[]]$pub_bytes) {
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2;
	$cert.Import($pub_bytes);
    $encKey = $cert.PublicKey.Key.Encrypt($key_bytes, $true);
	return $(B2H $encKey)
};

# private key decryption (pkek, server.key)
function p_k_d($key_bytes) {
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2;
    $cert.Import('server.pfx');
    $decKey = $cert.PrivateKey.Decrypt($(H2B $key_bytes), $true)
	return $decKey
};

$pkek = "3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971"
$bk = p_k_d $pkek
$file = '.\alabaster_passwords.elfdb.wannacookie'
e_d_file $bk $file $false