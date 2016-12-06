<?php
namespace Alisupplier\Core;

use Alisupplier\Core\Serialize\SerializerProvider;
use Alisupplier\Core\Util\SignatureUtil;
use Alisupplier\Core\Util\DateUtil;
use Alisupplier\Core\Policy\ClientPolicy;
use Alisupplier\Core\Policy\RequestPolicy;
use Alisupplier\Core\APIRequest;

class SyncAPIClient {
	public $clientPolicy;
	
	/**
	 *
	 * @param ClientPolicy $clientPolicy        	
	 */
	public function __construct(ClientPolicy $clientPolicy){
		$this->clientPolicy = $clientPolicy;
	}

	public function getCode() {
		$params = [
			'client_id'=>$this->clientPolicy->appKey,
			'site'=>'china',
			'redirect_uri'=>$this->clientPolicy->redirect_uri
		];
		$params['_aop_signature'] = SignatureUtil::Authsignature ( $params,  $this->clientPolicy );
		$urlRequest = 'http://gw.open.1688.com/auth/authorize.htm?'.http_build_query($params);
		header("location: ".$urlRequest);exit();
	}
	public function send(APIRequest $request, $resultDefiniation, RequestPolicy $requestPolicy) {
		$urlRequest = $this->generateRequestPath ( $request, $requestPolicy, $this->clientPolicy );
		if ($requestPolicy->useHttps) {
			if($this->clientPolicy->httpsPort==443){
				$urlRequest = "https://" . $this->clientPolicy->serverHost . $urlRequest;
			}else{
				$urlRequest = "https://" . $this->clientPolicy->serverHost .":".$this->clientPolicy->httpsPort . $urlRequest;
			}
		} else {
			if($this->clientPolicy->httpPort==80){
				$urlRequest = "http://" . $this->clientPolicy->serverHost . $urlRequest;
			}else{
				$urlRequest = "http://" . $this->clientPolicy->serverHost .":".$this->clientPolicy->httpPort . $urlRequest;
			}
		}
		
		$serializerTools = SerializerProvider::getSerializer ( $requestPolicy->requestProtocol );
		$requestData = $serializerTools->serialize ( $request->requestEntity );
		$requestData = array_merge ( $requestData, $request->addtionalParams );
		if ($requestPolicy->needAuthorization) {
			$requestData ["access_token"] = $request->accessToken;
		}
		if ($requestPolicy->requestSendTimestamp) {
			// $requestData ["_aop_timestamp"] = time();
		}
		$requestData ["_aop_datePattern"] = DateUtil::getDateFormatInServer ();
		if ($requestPolicy->useSignture) {
			if ($this->clientPolicy->appKey != null && $this->clientPolicy->secKey != null) {
				$pathToSign = $this->generateAPIPath ( $request, $requestPolicy, $this->clientPolicy );
				$signaturedStr = SignatureUtil::signature ( $pathToSign, $requestData,  $this->clientPolicy );
				$requestData ["_aop_signature"] = $signaturedStr;
			}
		}
		$ch = curl_init ();
		$paramToSign = "";
		foreach ( $requestData as $k => $v ) {
			$paramToSign = $paramToSign . $k . "=" . urlencode($v) . "&";
		}
		$paramLength = strlen ( $paramToSign );
		if ($paramLength > 0) {
			$paramToSign = substr ( $paramToSign, 0, $paramToSign - 1 );
		}
		if ($requestPolicy->httpMethod === "GET") {
			$urlRequest = $urlRequest . "?" . $paramToSign;
			curl_setopt ( $ch, CURLOPT_URL, $urlRequest );
			curl_setopt ( $ch, CURLOPT_HEADER, false );
			curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
			curl_setopt ( $ch, CURLOPT_CONNECTTIMEOUT, 120 );
			curl_setopt ( $ch, CURLOPT_POST, 0 );
			curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
			curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
			
//			$result = $newclient->get ( $urlRequest, $requestData );
			$data = curl_exec ( $ch );

		}
		else {
			curl_setopt ( $ch, CURLOPT_URL, $urlRequest );
			curl_setopt ( $ch, CURLOPT_HEADER, false );
			curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
			curl_setopt ( $ch, CURLOPT_CONNECTTIMEOUT, 120 );
			curl_setopt ( $ch, CURLOPT_POST, 1 );
			curl_setopt ( $ch, CURLOPT_POSTFIELDS, $paramToSign );
			curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
			curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
			$data = curl_exec ( $ch );
		}
		
		if ($data) {
			$content = $data;
			$deSerializerTools = SerializerProvider::getDeSerializer ( $requestPolicy->responseProtocol );
			$status = curl_getinfo ( $ch, CURLINFO_HTTP_CODE );
			
			curl_close ( $ch );
			if ($status >= 400 && $status <= 599) {
				$resultException = $deSerializerTools->buildException ( $content, $resultDefiniation );
				throw $resultException;
			} else {
				$resultDefiniation = $deSerializerTools->deSerialize ( $content, $resultDefiniation );
				return $resultDefiniation;
			}
		} else {
			$status = curl_getinfo ( $ch, CURLINFO_HTTP_CODE );
			curl_close ( $ch );
			return $status;
		}
	}
	public function httpclient(APIRequest $request,  RequestPolicy $requestPolicy) {
		$urlRequest = $this->generateRequestPath ( $request, $requestPolicy, $this->clientPolicy );
		if ($requestPolicy->useHttps) {
			if($this->clientPolicy->httpsPort==443){
				$urlRequest = "https://" . $this->clientPolicy->serverHost . $urlRequest;
			}else{
				$urlRequest = "https://" . $this->clientPolicy->serverHost .":".$this->clientPolicy->httpsPort . $urlRequest;
			}
		} else {
			if($this->clientPolicy->httpPort==80){
				$urlRequest = "http://" . $this->clientPolicy->serverHost . $urlRequest;
			}else{
				$urlRequest = "http://" . $this->clientPolicy->serverHost .":".$this->clientPolicy->httpPort . $urlRequest;
			}
		}

		$serializerTools = SerializerProvider::getSerializer ( $requestPolicy->requestProtocol );
		$requestData = $serializerTools->serialize ( $request->requestEntity );
		$requestData = array_merge ( $requestData, $request->addtionalParams );
		if ($requestPolicy->needAuthorization) {
			$requestData ["access_token"] = $request->accessToken;
		}
		if ($requestPolicy->requestSendTimestamp) {
			// $requestData ["_aop_timestamp"] = time();
		}
		$requestData ["_aop_datePattern"] = DateUtil::getDateFormatInServer ();
		if ($requestPolicy->useSignture) {
			if ($this->clientPolicy->appKey != null && $this->clientPolicy->secKey != null) {
				$pathToSign = $this->generateAPIPath ( $request, $requestPolicy, $this->clientPolicy );
				$signaturedStr = SignatureUtil::signature ( $pathToSign, $requestData, $this->clientPolicy );
				$requestData ["_aop_signature"] = $signaturedStr;
			}
		}
//		var_dump($requestData);
		$ch = curl_init ();
		$paramToSign = "";
		foreach ( $requestData as $k => $v ) {
			if(is_bool($v)){
				$v = empty($v)?'false':'true';
			}
			$paramToSign = $paramToSign . $k . "=" . $v . "&";
		}
//		var_dump($paramToSign);die();
		$paramLength = strlen ( $paramToSign );
		if ($paramLength > 0) {
			$paramToSign = substr ( $paramToSign, 0, $paramToSign - 1 );
		}
		if ($requestPolicy->httpMethod === "GET") {
			$urlRequest = $urlRequest . "?" . $paramToSign;
			curl_setopt ( $ch, CURLOPT_URL, $urlRequest );
			curl_setopt ( $ch, CURLOPT_HEADER, false );
			curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
			curl_setopt ( $ch, CURLOPT_CONNECTTIMEOUT, 120 );
			curl_setopt ( $ch, CURLOPT_POST, 0 );
			curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
			curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );

//			$result = $newclient->get ( $urlRequest, $requestData );
			$data = curl_exec ( $ch );
		} else {
			// var_dump($urlRequest);
			// var_dump($paramToSign);die();
			curl_setopt ( $ch, CURLOPT_URL, $urlRequest );
			curl_setopt ( $ch, CURLOPT_HEADER, false );
			curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
			curl_setopt ( $ch, CURLOPT_CONNECTTIMEOUT, 120 );
			curl_setopt ( $ch, CURLOPT_POST, 1 );
			curl_setopt ( $ch, CURLOPT_POSTFIELDS, $paramToSign );
			curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
			curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
			$data = curl_exec ( $ch );
		}

		if ($data) {
			$content = $data;
			$deSerializerTools = SerializerProvider::getDeSerializer ( $requestPolicy->responseProtocol );
			$status = curl_getinfo ( $ch, CURLINFO_HTTP_CODE );

			curl_close ( $ch );
			return ['state'=>$status,'data'=>json_decode($content,true)];
		} else {
			$status = curl_getinfo ( $ch, CURLINFO_HTTP_CODE );
			curl_close ( $ch );
			return $status;
		}
	}

	private function generateRequestPath(APIRequest $request, RequestPolicy $requestPolicy, ClientPolicy $clientPolicy) {
		$urlResult = "";
		if ($requestPolicy->accessPrivateApi) {
			$urlResult = "/api";
		} else {
			$urlResult = "/openapi";
		}
		
		$defs = array (
				$urlResult,
				"/",
				$requestPolicy->requestProtocol,
				"/",
				$request->apiId->version,
				"/",
				$request->apiId->namespace,
				"/",
				$request->apiId->name,
				"/",
				$clientPolicy->appKey 
		);
		
		$urlResult = implode ( $defs );
		
		return $urlResult;
	}
	private function generateAPIPath(APIRequest $request, RequestPolicy $requestPolicy, ClientPolicy $clientPolicy) {
		$urlResult = "";
		$defs = array (
				$urlResult,
				$requestPolicy->requestProtocol,
				"/",
				$request->apiId->version,
				"/",
				$request->apiId->namespace,
				"/",
				$request->apiId->name,
				"/",
				$clientPolicy->appKey 
		);
		
		$urlResult = implode ( $defs );
		
		return $urlResult;
	}
}