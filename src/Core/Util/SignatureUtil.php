<?php
namespace Alisupplier\Core\Util;

use Alisupplier\Core\Policy\RequestPolicy;
use Alisupplier\Core\Policy\ClientPolicy;
class SignatureUtil {
	
	/**
	 *
	 * @param unknown $path        	
	 * @param array $parameters        	
	 * @param RequestPolicy $requestPolicy        	
	 * @param ClientPolicy $clientPolicy        	
	 * @return string
	 */
	public static function signature($path, array $parameters, ClientPolicy $clientPolicy) {
//		var_dump($parameters);die();
		$paramsToSign = array ();
		foreach ( $parameters as $k => $v ) {
			$paramToSign = $k . $v;
			Array_push ( $paramsToSign, $paramToSign );
		}
		sort ( $paramsToSign );
		$implodeParams = implode ( $paramsToSign );
		$pathAndParams = $path . $implodeParams;
		$sign = hash_hmac ( "sha1", $pathAndParams, $clientPolicy->secKey, true );
		$signHexWithLowcase = bin2hex ( $sign );
		$signHexUppercase = strtoupper ( $signHexWithLowcase );
		return $signHexUppercase;
	}

	public static function Authsignature(array $parameters, ClientPolicy $clientPolicy){
		$paramsToSign = array ();
		foreach ( $parameters as $k => $v ) {
			$paramToSign = $k . $v;
			Array_push ( $paramsToSign, $paramToSign );
		}
		sort ( $paramsToSign );
		$implodeParams = implode ( $paramsToSign );
		$sign = hash_hmac ( "sha1", $implodeParams, $clientPolicy->secKey, true );
		$signHexWithLowcase = bin2hex ( $sign );
		$signHexUppercase = strtoupper ( $signHexWithLowcase );
		return $signHexUppercase;
	}
}