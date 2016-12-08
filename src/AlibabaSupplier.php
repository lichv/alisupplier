<?php
namespace Alisupplier;

use Alisupplier\Core\APIId;
use Alisupplier\Core\APIRequest;
use Alisupplier\Core\APIParam;
use Alisupplier\Core\SyncAPIClient;
use Alisupplier\Core\Policy\ClientPolicy;
use Alisupplier\Core\Policy\DataProtocol;
use Alisupplier\Core\Policy\RequestPolicy;




/**
 * API调用的入口
 */
class AlibabaSupplier {

	private $serverHost = "gw.open.1688.com";
	private $httpPort = 80;
	private $httpsPort = 443;
	private $appKey;
	private $secKey;
	private $syncAPIClient;

	private $redirect_uri;
	
	public function setServerHost($serverHost) {
		$this->serverHost = $serverHost;
	}
	public function setHttpPort($httpPort) {
		$this->httpPort = $httpPort;
	}
	public function setHttpsPort($httpsPort) {
		$this->httpsPort = $httpsPort;
	}
	public function setAppKey($appKey) {
		$this->appKey = $appKey;
	}
	public function setSecKey($secKey) {
		$this->secKey = $secKey;
	}
	public function setRedirectUrl($url){
		$this->redirect_uri = $url;
	}

	public function initClient() {
		$clientPolicy = new ClientPolicy ();
		$clientPolicy->appKey = $this->appKey;
		$clientPolicy->secKey = $this->secKey;
		$clientPolicy->httpPort = $this->httpPort;
		$clientPolicy->httpsPort = $this->httpsPort;
		$clientPolicy->serverHost = $this->serverHost;
		$clientPolicy->redirect_uri = $this->redirect_uri;
		
		$this->syncAPIClient = new SyncAPIClient ( $clientPolicy );
	}
	
	public function getAPIClient() {
		if ($this->syncAPIClient == null) {
			$this->initClient ();
		}
		return $this->syncAPIClient;
	}

	/**
	 * 授权入口
	 */
	public function getCode(){
		$this->getAPIClient()->getCode();
	}

	/**
	 * 根据授权码换取授权令牌
	 * @param string $code 授权码
	 * @return array 授权令牌数组
	 */
	public function getToken($code) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=true;
		$reqPolicy->useHttps=true;
		$reqPolicy->requestProtocol=DataProtocol::param2;
		
		$request = new APIRequest ();
		$request->addtionalParams["code"]=$code;
		$request->addtionalParams["grant_type"]="authorization_code";
		$request->addtionalParams["need_refresh_token"]=true;
		$request->addtionalParams["client_id"]=$this->appKey;
		$request->addtionalParams["client_secret"]=$this->secKey;
		$request->addtionalParams["redirect_uri"]=$this->redirect_uri;
		$apiId = new APIId ("system.oauth2", "getToken", $reqPolicy->defaultApiVersion);
		$request->apiId = $apiId;

		$result = $this->getAPIClient()->httpclient($request, $reqPolicy);
		if($result['state']==200){
			$this->setAccessToken($result['data']);
		}
		
		return $result;
	}

	/**
	 * 根据refresh_token换取授权令牌
	 * @return array 授权令牌数组
	 */
	public function regetToken() {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=true;
		$reqPolicy->useHttps=true;
		$reqPolicy->requestProtocol=DataProtocol::param2;

		$accessToken = $this->getAccessTokenSource();

		$request = new APIRequest ();
		$request->addtionalParams["refresh_token"]=$accessToken['refresh_token'];
		$request->addtionalParams["grant_type"]="refresh_token";
		$request->addtionalParams["need_refresh_token"]=true;
		$request->addtionalParams["client_id"]=$this->appKey;
		$request->addtionalParams["client_secret"]=$this->secKey;
		$request->addtionalParams["redirect_uri"]=$this->redirect_uri;
		$apiId = new APIId ("system.oauth2", "getToken", $reqPolicy->defaultApiVersion);
		$request->apiId = $apiId;
		$result = $this->getAPIClient()->httpclient($request, $reqPolicy);
		if($result['state']==200){
			$this->setAccessToken($result['data']);
		}

		return $result;
	}

	/**
	 * 获取存储在本地的授权令牌
	 * @return array 授权令牌数组
	 */
	public function getAccessTokenSource(){
		$result = false;
		$content = '';
		$file = __DIR__.'/access_token.json';
		if(file_exists($file)){
			$handle = fopen($file, 'r');
			while(!feof($handle)){
				$content .= fread($handle, 255);
			}
			fclose($handle);
		}
		if(!empty($content)){
			$result = json_decode($content,true);
		}
		return $result;
	}

	/**
	 * 获取存储在本地的授权令牌，refresh_token有效access_token失效时更新授权令牌，refresh_token有效期不足30天换取refresh_token
	 * @return array 授权令牌数组
	 */
	public function getAccessToken(){
		$result = $this->getAccessTokenSource();
		$now = time();
		if($result['expires_time']<$now && $result['refresh_token_timeout']>$now ){
			$this->regetToken();
		}
		if(isset($result['refresh_token_timeout']) && $result['refresh_token_timeout']>$now && $result['refresh_token_timeout']-86400*30<$now){
			$this->postponeToken();
		}
		return $this->getAccessTokenSource();
	}

	/**
	 * 存储在本地的授权令牌
	 * @return array 授权令牌数组
	 */
	public function setAccessToken($accessToken){
		$data = ['access_token'=>$accessToken['access_token']];
		if(!empty($accessToken['expires_in'])){
			$accessToken['expires_time'] = time()+$accessToken['expires_in'];
			$data['expires_time'] = $accessToken['expires_time'];
		}
		if(!empty($accessToken['refresh_token'])){
			$data['refresh_token'] = $accessToken['refresh_token'];
		}
		if(!empty($accessToken['refresh_token_timeout'])){
			$data['refresh_token_timeout'] = strtotime(substr($accessToken['refresh_token_timeout'],0,14));
		}
		$file = __DIR__.'/access_token.json';
		$stream = fopen($file, 'w+b');
		fwrite($stream, json_encode($data));
		fclose($stream);

		return true;
	}
	
	
	/**
	 * 刷新refresh_token
	 * @return array 授权令牌
	 */
	public function postponeToken() {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=true;
		$reqPolicy->useHttps=true;
		$reqPolicy->requestProtocol=DataProtocol::param2;

		$accessToken = $this->getAccessToken();
		
		$request = new APIRequest ();
		$request->addtionalParams["refresh_token"]=$accessToken['refresh_token'];
		$request->addtionalParams["grant_type"]="refresh_token";
		$request->addtionalParams["client_id"]=$this->appKey;
		$request->addtionalParams["client_secret"]=$this->secKey;
		$apiId = new APIId ("system.oauth2", "postponeToken", $reqPolicy->defaultApiVersion);
		$request->apiId = $apiId;

		$result = $this->getAPIClient()->httpclient($request, $reqPolicy);
		if($result['state']==200){
			$this->setAccessToken($result['data']);
		}
		return $result;
	}

	/**
	 * 通用API调用接口
	 * @param  RequestPolicy $reqPolicy 请求规则
	 * @param APIRequest $request 请求数据
	 * @return array 接口调用结果
	 */
	public function run(RequestPolicy $reqPolicy,APIRequest $request){
		if($reqPolicy->needAuthorization){
			$accessToken = $this->getAccessToken();
			$request->accessToken = $accessToken['access_token'];
		}
			
		return $this->getAPIClient()->httpclient($request, $reqPolicy);
	}

	/**
	 * 根据类目ID获取类目属性
	 * @param  APIParam $param 请求参数
	 * @param  Long $param->categoryID	必选 类目ID
	 * @param  String $param->webSite 必选 站点信息，指定调用的API是属于国际站(alibaba)还是1688网站(1688)
	 * @return array 属性列
	 */
	public function categoryAttributeGet(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.category.attribute.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$res = $this->run($reqPolicy,$request);
		if($res['state']==200){
			$result = ['state'=>200,'data'=>$res['data']['attributes']];
		}else{
			$result = $res;
		}
		return $result;
	}


	/**
	 * 根据父级类目查询子类
	 * @param  APIParam $param 请求参数
	 * @param  Long $param->categoryID	必选 类目ID
	 * @param  String $param->webSite 必选 站点信息，指定调用的API是属于国际站(alibaba)还是1688网站(1688)
	 * @return array 属性列
	 */
	public function categoryGet(APIParam $param) {
		$result = [];
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=false;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.category.get", 1);
		$request->apiId = $apiId;
		$request->requestEntity=$param;

		$res = $this->run($reqPolicy,$request);
		if($res['state']==200){
			$result = ['state'=>200,'data'=>$res['data']['categoryInfo']];
		}else{
			$result = $res;
		}
		return $result;
	}

	/**
	 * 根据1688的类目获取标准化产品单元信息
	 * @param  APIParam $param 请求参数
	 * @param  Long $param->categoryID	必选 类目ID
	 * @param  String $param->index 必选 当前页，无默认值
	 * @param  String $param->size 必选 每页多少记录，无默认值
	 * @return array 属性列
	 */
	public function categorySearchSPUInfo(APIParam $param) {
		$result = [];
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="GET";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.category.searchSPUInfo", 1);
		$request->apiId = $apiId;
		$request->requestEntity=$param;

		$res = $this->run($reqPolicy,$request);
		if($res['state']==200){
			$result = $res['data'];
			$result['state']=200;
		}else{
			$result = $res;
		}
		return $result;
	}

	//发布一个新商品，此API为国际站与1688通用
	public function productAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	// /将某个商品删除到回收站中，可在网站手工清除或恢复
	public function productDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.delete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改商品详细信息
	public function productEdit(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.edit", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//商品转为过期
	public function productExpire(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.expire", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//由商品ID获取商品详细信息
	public function productInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取商品列表
	public function productGetList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.getList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取是否启用自定义分类
	public function productGroupGetSwitch(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.group.getSwitch", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//设置是否启用自定义分类
	public function productGroupSetSwitch(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.group.setSwitch", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//产品是否可以修改
	public function productIsModifiable(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.isModifiable", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//增量修改产品库存
	public function productModifyStock(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.modifyStock", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//重发商品
	public function productRepost(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.repost", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//创建相册
	public function photobankAlbumAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.album.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//删除相册
	public function photobankAlbumDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.album.delete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取相册列表
	public function photobankAlbumGetList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.album.getList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改授权用户自身的相册
	public function photobankAlbumModify(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.album.modify", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//上传图片
	public function photobankPhotoAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=false;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.photo.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//删除图片
	public function photobankPhotoDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.photo.delete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量删除图片
	public function photobankPhotoDeleteBatch(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.photo.deleteBatch", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取指定相册中图片列表
	public function photobankPhotoGetList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.photo.getList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改图片信息
	public function photobankPhotoModify(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.photobank.photo.modify", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取交易订单的物流信息(买家视角)
	public function logisticsInfosForBuyer(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.logistics", "alibaba.trade.getLogisticsInfos.buyerView", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取交易订单的物流信息(卖家视角)
	public function logisticsInfosForSeller(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.logistics", "alibaba.trade.getLogisticsInfos.sellerView", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取交易订单的物流信息(买家视角)
	public function logisticsTraceInfosForBuyer(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.logistics", "alibaba.trade.getLogisticsTraceInfo.buyerView", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取交易订单的物流信息(卖家视角)
	public function logisticsTraceInfosForSeller(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.logistics", "alibaba.trade.getLogisticsTraceInfo.sellerView", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取订单的发票信息
	public function tradeInvoiceInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.invoice.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//支付单生成
	public function tradePaymentOrderCreate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.payment.order.bank.create", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//交易地址编码列表
	public function tradeAddressList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.addresscode.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//交易地址下一级信息
	public function tradeAddressChildrenInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.addresscode.getchild", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//交易地址解析
	public function tradeAddressParse(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.addresscode.parse", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//订单预览
	public function tradePreorder(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.general.preorder", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//订单创建
	public function tradeOrderCreate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.generalOrder.create", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//订单查询买家角度
	public function tradeInfoForBuyer(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.get.buyerView", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//订单查询卖家角度
	public function tradeInfoForSeller(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.get.sellerView", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//订单列表查询买家角度
	public function tradeBuyerOrderList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.getBuyerOrderList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//订单列表查询卖家角度
	public function tradeRefund(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.refund.OpAgreeReturnGoods", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//退款单查询卖家角度
	public function tradeRefundForSeller(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.refund.OpQueryBatchRefundByOrderIdAndStatus", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//退款单查询卖家角度
	public function tradeRefundInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.refund.OpQueryOrderRefund", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//退款操作记录卖家角度
	public function tradeRefundOperationList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.refund.OpQueryOrderRefundOperationList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//退款操作记录卖家角度
	public function tradeRefundList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.trade", "alibaba.trade.refund.queryOrderRefundList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//会员信息省份编码
	public function memberAreaCode(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "areaCode.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量转换memberId到loginId
	public function memberIds2LoginIds(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "convertLoginIdsByMemberIds", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量转换loginId到memberId
	public function mLoginIds2emberIds(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "convertMemberIdsByLoginIds", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取会员诚信信息
	public function creditInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "creditInfo.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取会员信息
	public function memberInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "member.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取公司信息
	public function companyInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "company.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//取消一个橱窗推荐产品(目前诚信通用户可用)
	public function showCancelRecommend(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "industry.showwindow.cancelRecommendOffer", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取某个卖家已经推荐的橱窗产品列表
	public function showRecommendList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "industry.showwindow.doQueryRecommOfferList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//推荐一个产品为橱窗产品(目前诚信通用户可用)
	public function showRecommendDo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "industry.showwindow.doRecommendOffer", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取某个卖家的相关橱窗信息(目前诚信通用户可用)
	public function showQuery(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "industry.showwindow.query", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站已登录会员获取指定产品是否可以修改的信息
	public function offerCanModify(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.canModify.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站已登录会员获取指定产品是否可以修改的信息
	public function offerDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.delete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站已登录卖家会员批量的设置指定offerID产品信息为过期商品的功能
	public function offerExpire(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.expire", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取单个产品信息
	public function offerInfo($id) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.get", 1);
		$request->apiId = $apiId;

		$param = new \Alisupplier\Core\APIParam();
		$param->setOfferId($id);
		$param->setReturnFields('skuPics,isPrivateOffer,isPriceAuthOffer,isPicAuthOffer,offerId,isPrivate,detailsUrl,type,tradeType,postCategryId,offerStatus,memberId,subject,details,qualityLevel,imageList,productFeatureList,isOfferSupportOnlineTrade,tradingType,isSupportMix,unit,priceUnit,amount,amountOnSale,saledCount,retailPrice,unitPrice,priceRanges,termOfferProcess,freightTemplateId,sendGoodsId,productUnitWeight,freightType,isSkuOffer,isSkuTradeSupported,skuArray,gmtCreate,gmtModified,gmtLastRepost,gmtApproved,gmtExpire');
		$request->requestEntity=$param;
		$res = $this->run($reqPolicy,$request);
		if($res['state']==200){
			$result = $res['data']['result'];
			$result['state']=200;
		}else{
			$result = $res;
		}

		return $result;
	}

	//中文站会员所有的产品
	public function offerList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.getAllOfferList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站会员已发布的产品
	public function publishOfferList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.getPublishOfferList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站登录会员修改offer的功能
	public function offerModify(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.modify", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站登录会员修改产品的标题和价格信息
	public function offerModifyIncrement(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.modify.increment", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站登录会员修改产品的标题和价格信息
	public function offerModifyStock(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.modify.stock", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站登录会员发布offer的功能
	public function offerPublish(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.new", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//中文站登录会员批量重发指定offerID产品信息上网
	public function offerRepost(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.repost", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//搜索产品信息
	public function offerSearch(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offer.search", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量修改产品信息
	public function offersModify(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offers.modify", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}


	//根据父类目ID获取其子类目信息
	public function categoryListByParent(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=false;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "category.getCatListByParentId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过大市场叶子类目id，获取该类目的发布类目路径
	public function categoryPath(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "category.getCatePath", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据类目ID获取商品发布类目信息
	public function categoryList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "category.getPostCatList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据类目ID获取商品发布类目信息
	public function categoryLevelAttr(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "category.level.attr.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过输入关键词,搜索相关的类目ID
	public function categorySearch(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "category.search", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据叶子类目ID获取类目发布属性信息
	public function categoryFeatures(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "offerPostFeatures.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据叶子类目ID获取产品属性信息
	public function categoryAttributes(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "productAttributes.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过输入用户填写的某个类目关键产品属性，返回该类目产品属性的SPU信息
	public function categorySPUByAttributes(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "spubyattribute.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过输入用户填写的某个类目关键产品属性，返回该类目其对应的交易属性信息
	public function categoryTradeAttributes(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "tradeAttributes.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//创建相册
	public function albumCreate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.album.create", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//删除相册
	public function albumDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.album.delete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据相册id获取相册
	public function albumInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.album.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取当前用户相册列表
	public function albumList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.album.list", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取当前用户相册列表
	public function albumModify(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.album.modify", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量删除图片
	public function imageDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.image.deleteByIds", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取当前用户的图片信息
	public function imageInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.image.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取当前用户的图片信息
	public function imageList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.image.list", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改当前用户的图片信息
	public function imageModify(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.image.modify", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//上传图片
	public function imageUpload(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.image.upload", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取当前用户信息，包括可用空间和总空间等
	public function imageProfile(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "ibank.profile.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//目前只支持网商大额转账，不支持非网商银行付款订单的确认收货
	public function tradeOrderAddress(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.cn.alibaba.open.trade.order.receiveGoods", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取指定会员在阿里巴巴中文站上的发货地址列表信息(只能查自己的信息)
	public function tradeOrderAddressList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "trade.freight.sendGoodsAddressList.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取指定会员在阿里巴巴中文站上的发货地址列表信息(只能查自己的信息)
	public function logisticsCompanyList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "trade.logisticsCompany.logisticsCompanyList.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//支持多笔订单（暂定最多10笔每次）同时提交评价，并且只支持卖家向买家的评价
	public function tradeOrderBatchRate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "trade.order.batch.rate", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询单个订单详情
	public function tradeOrderInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "trade.order.detail.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询订单列表
	public function tradeOrderList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "trade.order.list.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改订单价格
	public function tradeOrderModifyOrderPrice(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "trade.order.modifyOrderPrice", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//当前会话会员的交易订单详情
	public function tradeOrderDetail(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "trade.order.orderDetail.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询当前会话会员的交易订单列表
	public function tradeOrderGetList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "trade.order.orderList.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取阿里巴巴中国网站指定会员的混批和发票设置信息
	public function wholesale(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "wholesale.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//代销市场offer相似款搜索，此API为定向招募开放
	public function searchDaixiaoSimilar(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.offer.daixiao.similar.pages", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//代销市场淘宝offer的相似款搜索，此API为定向招募开放
	public function searchDaixiaoTBSimilar(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.offer.daixiao.t2b.similar.pages", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询淘宝卖家的商品在1688的同款及相似款信息，此API为定向招募开放
	public function searchGraphOfferInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.offer.info", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询淘宝商品在1688的同款商品信息，此API为定向招募开放
	public function searchGraphOfferSame(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.offer.same", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//分页查询淘宝商品在1688的同款商品信息，此API为定向招募开放
	public function searchGraphOfferSamePages(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.offer.same.pages", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询淘宝商品在1688的相似款商品信息，此API为定向招募开放
	public function searchGraphOfferSimilar(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.offer.similar", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//分页查询淘宝商品在1688的相似款商品信息，此API为定向招募开放
	public function searchGraphOfferSimilarPages(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.offer.similar.pages", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询淘宝商品在1688的广告类同款商品信息，此API为定向招募开放
	public function searchGraphP4PSame(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.p4p.same", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询淘宝商品在1688的相似款广告推广类商品信息，此API为定向招募开放
	public function searchGraphP4PSimilar(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.graph.p4p.similar", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//ISV代销版猜你喜欢接口1
	public function searchGuessOfferDaixiaov1(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.guess.offer.daixiao.version1", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//ISV代销版猜你喜欢接口2
	public function searchGuessOfferDaixiaov2(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "alibaba.search.guess.offer.daixiao.version2", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//用户在发布offer时候，需要选择对应的发布类目，类目作弊就是用来检测选择的类目跟发布的offer信息是否匹配
	public function searchCategoryCheatding(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=false;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "search.category.cheating", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//判断用户填写的属性是否存在滥用，比如属性值多个重复使用，属性值过长，以及属性值无意义等
	public function searchPropertiesAbuse(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=false;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "search.properties.abuse", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//用来判断，用户标题和属性中填写的信息是否一致，是否存在冲突的关键属性
	public function searchPropertiesInconsistent(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=false;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "search.title.properties.inconsistent", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//用来判断，用户标题和属性中填写的信息是否一致，是否存在冲突的关键属性
	public function searchTitleStuffing(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=false;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("cn.alibaba.open", "search.title.stuffing", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//新增运费模板，国际站可用此接口初始化运费模板，1688此接口无效
	public function logisticsFreightTemplateAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.logistics.freightTemplate.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取运费模板列表。1688有两类特殊运费模板，不在此接口返回：不传运费模板表示使用运费说明；传入1表示卖家承担运费
	public function logisticsFreightTemplateList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.logistics.freightTemplate.getList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//运费模板详情描述
	public function logisticsDeliveryTemplateInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "e56.delivery.template.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//运费模板详情描述
	public function logisticsDeliveryTemplateList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "e56.delivery.template.list", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取提供该服务的物流公司列表
	public function logisticsDeliveryCompanies(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "e56.logistics.companies.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//实现无需物流（虚拟）发货,使用该接口发货，交易订单状态会直接变成卖家已发货
	public function logisticsDeliveryDummySend(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "e56.logistics.dummy.send", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//用户调用该接口可实现自己联系发货（线下物流），使用该接口发货，交易订单状态会直接变成卖家已发货
	public function logisticsDeliveryOfflineSend(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "e56.logistics.offline.send", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据交易订单ID, 获取该订单下的物流单列表
	public function logisticsDeliveryByOrder(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "e56.logistics.orders.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据交易订单ID, 获取该订单下的物流单列表
	public function logisticsDeliveryTraceInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "e56.logistics.trace.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//卖家新增客户关系
	public function customerAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.customer.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//卖家删除客户关系
	public function customerBatchDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.customer.batchdelete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//编辑客户关系
	public function customerEdit(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.customer.edit", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据标签获取当前卖家的会员信息
	public function customerGroupInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.customer.group.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量修改客户等级
	public function customerRelationBatchEdit(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.customer.relation.batchEdit", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据等级获取当前卖家的会员信息
	public function customerRelationInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.customer.relation.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//设置会员等级升迁体系
	public function customerSetGrade(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.customer.setGrade", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据交易信息获取当前卖家的会员信息
	public function customerTradeInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.customer.trade.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//卖家新增某个标签
	public function customerGroupAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.groups.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//卖家删除某个标签
	public function customerGroupDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.groups.delete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//卖家删除某个标签
	public function customerGroupDetail(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.groups.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//卖家修改标签名称
	public function customerGroupNameUpdate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "acrm.groups.name.update", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//创建1688营销短链
	public function marketingShortLinkCreate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.cn.marketing.shortlink.create", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询1688营销短链
	public function marketingShortLinkQuery(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.cn.marketing.shortlink.query", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//分页读取当前短信任务中圈子列表
	public function marketingShortMsgCircleByPageNum(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.cn.marketing.shortmsg.readCircleByPageNum", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//读取短信任务信息
	public function marketingShortMsgReadMsgTask(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.cn.marketing.shortmsg.readMsgTask", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//分页获取未完成任务的TaskId列表,可指定获取的任务Id列表大小
	public function marketingShortMsgReadMsgTaskList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.cn.marketing.shortmsg.readTodoMsgTaskIdList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//返回短信任务检查结果
	public function marketingShortMsgReturnCheckResult(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.cn.marketing.shortmsg.returnCheckResult", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//返回短信任务发送详情
	public function marketingShortMsgReturnSendDetail(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.cn.marketing.shortmsg.returnSendDetail", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取指定会员（供应商）的自定义商品分类信息
	public function categoryGetSelfCatList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "category.getSelfCatlist", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取阿里巴巴中国网站会员是否已经开启自定义分类功能
	public function offerGroupHasOpened(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "offerGroup.hasOpened", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//阿里巴巴中国网站会员开启或关闭自定义分类功能
	public function offerGroupSet(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "offerGroup.set", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量获取指定产品所属的自定义分类ID
	public function userCategoryOfferIds(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "userCategory.get.offerIds", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量添加多个产品到一个自定义分类下
	public function userCategoryOfferAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "userCategory.offers.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量移除多个产品的一个自定义分类
	public function userCategoryOfferRemove(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "userCategory.offers.remove", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取对应会员的“阿里助手”业务功能系统封装的URL地址
	public function myalibabaGetUri(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "myalibaba.getUri", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取指定offer的修改地址
	public function offerGetEditUri(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "offer.getEditUri", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取获取对应会员的“发布供求信息”业务功能系统封装的URL地址
	public function offerGetPostUri(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "offer.getPostUri", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取对应会员的“我已买到的货品”业务功能系统封装的URL地址
	public function tradeGetBuyerOrderListUri(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "trade.getBuyerOrderListUri", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取对应offerid的“下单”业务功能系统封装的URL地址
	public function tradeGetMakeOrderUri(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "trade.getMakeOrderUri", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取对应会员的“我已卖出的货品”业务功能系统封装的URL地址
	public function tradeGetSellerOrderListUri(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "trade.getSellerOrderListUri", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//ISV获取自己名下的应用最近一个月的到期的订单信息列表
	public function getAppExpire(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "app.expire.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//ISV获取自己名下的应用最近一个月的订购的订单信息列表
	public function getAppOrder(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "app.order.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//ISV获取自己名下的应用最近一个月的订购的订单信息列表
	public function getSystemTime(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=false;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=false;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "system.time.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//对接企业员工账号绑定1688子账号
	public function caigouAccountBindSubAccount(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.account.bindAccount", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//为某个操作员快速创建一个子帐号
	public function caigouAccountCreateSubAccount(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.account.createSubAccount", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取主账号下所有的子账号绑定信息
	public function caigouAccountListSubAccount(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.account.listSubAcccounts", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//上传附件
	public function caigouAttachmentUpload(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.attachment.upload", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过询价单id获取询价单
	public function caigouGetBuyOfferById(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.buyOffer.getBuyOfferById", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据prId查询询价单列表
	public function caigouGetBuyOfferByPrId(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.buyOffer.queryBuyOfferByPrId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//关闭询价单
	public function caigouGetBuyOfferClose(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.buyoffer.closeBuyOffer", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//发布询价单
	public function caigouGetBuyOfferPost(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.buyoffer.postBuyoffer", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//寻源单列表分页查询接口，包括询价单、竞价单、招标单等
	public function caigouGetBuyOfferQueryList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.buyoffer.queryList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//新增自定义类目，采购使用
	public function caigouAddUserCategory(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.category.addUserCategory", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//删除自定义类目，只能删除没有叶子节点的类目，如果有叶子节点，要先把叶子节点删除，再删除该类目
	public function caigouDeleteUserCategory(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.category.deleteUserCategory", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据id获取类目信息
	public function caigouGetById(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.category.getById", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改自定义类目
	public function caigouModifyUserCategory(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.category.modifyUserCategory", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询所有自定义类目
	public function caigouCategoryList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.category.queryAll", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//采购上传图片
	public function caigouImageUpload(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.image.upload", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改线下成交信息订单状态接口
	public function caigouUpdateOrderStatus(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.order.updateOrderStatus", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//发布产品信息，多次发布同一个产品不会产生重复数据，操作人员编号需要绑定后才能操作
	public function caigouAddProduct(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.product.addProduct", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//给产品批量修改自定义类目
	public function caigouModifyClassifyProduct(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.product.classifyProduct", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//给产品批量修改自定义类目
	public function caigouDeleteProductById(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.product.deleteProductById", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//更新产品信息，根据产品编号更新产品
	public function caigouModifyProduct(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.product.modifyProduct", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过用户编号、产品名、产品编号等属性分页查询产品列表
	public function caigouQueryProduct(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.product.queryProduct", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据产品编号查询产品列表
	public function caigouQueryProductByCode(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.product.queryProductByCodeList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过产品id获取产品详情
	public function caigouQueryProductById(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.product.queryProductById", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过产品id获取产品详情
	public function caigouAddProductQuote(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.productquote.addProductQuote", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改产品报价
	public function caigouModifyProductQuote(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.productquote.modifyProductQuote", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//产品报价上下架，控制该报价是否在目录商城展示
	public function caigouModifyProductQuoteStatus(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.productquote.modifyStatus", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//删除购物车中的货品
	public function caigouDeletePurchaseItems(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.purchase.deletePurchaseItems", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过报价单ID获取报价详情接口
	public function caigouGetQuotationDetail(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.quotation.buyerGetQuotationDetail", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过询价单ID获取下面报价单详情列表
	public function caigouGetQuotationListByBuyOfferId(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.quotation.buyerGetQuotationListByBuyOfferId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}


	//根据id删除产品报价
	public function caigouDeleteProductQuote(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.quote.deleteProductQuote", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据产品id查询对应的产品报价列表
	public function caigouQuoteListByProductId(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.quote.queryListByProductId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据供应商memberId获取供应商信息
	public function caigouGetSupplier(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.supplier.getSupplier", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据供应商memberId获取供应商信息
	public function caigouSupplierImport(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.supplier.import", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量查询采购商的供应商库信息，用于采购业务，供应商对接
	public function caigouSupplierMapping(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigou.api.supplier.querySupplierMapping", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量查询采购商的供应商库信息，用于采购业务，供应商对接
	public function caigouAddPurchaseitem(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigoumall.purchaseitem.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询采购商城报价库存
	public function caigouGetQuoteAmount(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigoumall.quote.amount.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//采购商城报价分组查询
	public function caigouGetQuoteOrderGroup(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "caigoumall.quote.order.group", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//游标式获取失败的消息列表
	public function caigouPushCursorMessageList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "push.cursor.messageList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//确认消息已经被消费成功
	public function caigouPushMessageConfirm(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "push.message.confirm", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询式获取发送的消息列表
	public function caigouPushMessageList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "push.query.messageList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//自动创建订单
	public function distributorAutoCreateOrder(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.autoCreateOrder", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//【已废弃】确认采购单
	public function distributorConfirmOrder(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.confirmOrder", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//删除采购单
	public function distributorDeleteSupplyOrder(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.deleteSupplyOrder", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//传淘宝代销
	public function distributorDownloadConsignSell(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.downloadConsignSell", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//一键代销
	public function distributorFastConsign(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.fastConsign", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//忽略采购单
	public function distributorIgnoreSupplyOrder(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.ignoreSupplyOrder", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//关联代销关系
	public function distributorLinkConsignSellItem(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.linkConsignSellItem", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取可代销产品列表
	public function distributorListForAllConsignment(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.listForAllConsignment", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取已代销产品列表
	public function distributorListForAlreadyConsignment(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.listForAlreadyConsignment", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取采购单列表
	public function distributorListSupplyOrders(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.listSupplyOrders", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改采购单信息
	public function distributorModifySupplyOrder(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.modifySupplyOrder", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据渠道商ID和商品ID和SPECID查询指定SKU下商品的折扣后的代销价格和库存
	public function distributorQuerySkuBySpecId(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.querySkuBySpecId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//规格同步
	public function distributorSyncTbSkuInfo(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.syncTbSkuInfo", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//取消代销关系
	public function distributorUnLinkConsignSellItem(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.distributor.unLinkConsignSellItem", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//添加产品线
	public function productlineAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.productline.addProductLine", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//删除产品线
	public function productlineDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.productline.deleteProductLine", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询产品分组信息
	public function productlineQueryConsigner(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.productline.queryConsignerProductlines", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改产品分组
	public function productlineUpdate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.productline.updateProductLine", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//添加等级
	public function relationAddGroup(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.addGroup", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//供应商批量修改分组等级
	public function relationChangeGroup(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.changeGroup", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//供应商批量修改分组等级
	public function relationDeleteGroup(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.deleteGroup", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//分销商终止关系,立刻生效
	public function relationEndConsignRelationByConsigner(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.endConsignRelationByConsigner", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//供应商终止关系，需要关系最终终结会在15天以后
	public function relationEndConsignRelationBySupplierId(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.endConsignRelationBySupplierId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过分销商ID获取代销概览
	public function relationGetOverviewByConsignerId(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.getOverviewByConsignerId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过供应商Id获取概述信息
	public function relationGetOverviewBySuppliersId(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.getOverviewBySuppliersId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询所有等级信息
	public function relationQueryConsignerGroups(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.queryConsignerGroups", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过供应商userId查询分销商列表
	public function relationQueryConsigners(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.queryConsigners", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//通过分销商 userID 获取 供应商列表
	public function relationQuerySuppliers(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.querySuppliers", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//供应商批量修改分组等级
	public function relationUpdateAllRightsRightType(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.updateAllRightsRightType", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改等级名称
	public function relationUpdateGroup(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.relation.updateGroup", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询权益设置
	public function rightsQueryAllRights(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.rights.queryAllRights", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//修改权益设置
	public function rightsUpdateAllRights(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.rights.updateAllRights", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//代销市场商品搜索服务
	public function searchDaixiaoOffer(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.search.daixiao.offer.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//代销市场直接搜索商品结果较少时，可以使用此API搜索进行相关性补足搜索
	public function searchDaixiaoOfferExt(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.search.daixiao.offer.getext", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//推荐代销市场的供应商
	public function searchDaixiaoRecomCompany(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.search.daixiao.recom.company", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//推荐代销市场的商品
	public function searchDaixiaoRecomOffer(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.search.daixiao.recom.offer", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//新增产品产品线关系
	public function supplierAddProductlineRelation(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.supplier.addProductlineRelation", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取供应商可代销产品列表
	public function supplierListForAllConsignment(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.supplier.listForAllConsignment", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//变更产品产品线关系
	public function supplierModifyProductlineRelation(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.supplier.modifyProductlineRelation", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//变更产品产品线关系
	public function supplierRemoveProductlineRelation(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.supplier.removeProductlineRelation", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//获取支持订单可视化的订单ID列表
	public function processOrderList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "tgc.process.order.getlist", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//提交订单生产详情信息
	public function processPostDetail(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "tgc.process.post.detail", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//提交订单预计发货时间
	public function processPostExpectedTime(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "tgc.process.post.expected.time", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//提交订单生产状态
	public function processPostStatus(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "tgc.process.post.status", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量更新1688系统中的大货订单信息
	public function erpBatchUpdateBulk(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.manufacture.batchUpdateBulk", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量更新1688系统中的打样订单信息
	public function erpBatchUpdateFent(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.manufacture.batchUpdateFent", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//拉取ERP系统中一个时间段内的大货订单信息列表
	public function erpPullBulkDataList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.manufacture.pullBulkDataList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//拉取ERP系统中一个时间段内的大货订单编码(货号)列表
	public function erpPullBulkGoodsCodes(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.manufacture.pullBulkGoodsCodes", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//拉取ERP系统中一个时间段内的大货订单编码(货号)列表
	public function erpPullFentDataList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.manufacture.pullFentDataList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量推送生产计划 1.此接口幂等 2.当planDate在1688 系统中已存在，则为更新操作
	public function erpPushProductionPlan(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.manufacture.pushProductionPlan", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//对接产品批量新增更新接口
	public function erpProductBatchAddUpdate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.product.batchAddUpdate", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//对接产品批量删除
	public function erpProductBatchDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.product.batchDelete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//系统对接产品批量查询接口
	public function erpProductBatchGetByCodeList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.product.batchGetByCodeList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//对接产品单条查询接口
	public function erpProductGetByCode(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.product.getByCode", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//对接产品全量分页查询接口
	public function erpProductQueryAll(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.product.queryAll", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//销售单列表查询接口
	public function erpSalesOrderPullDataList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.salesOrder.pullDataList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//销售单ID清单获取接口
	public function erpSalesOrderPullIds(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.salesOrder.pullIds", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//用户自定义类目批量新增更新
	public function erpUserCategoryBatchAddUpdate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.userCategory.batchAddUpdate", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//自定义类目批量删除
	public function erpUserCategoryBatchDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.userCategory.batchDelete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//用户自定义类目单条查询
	public function erpUserCategoryGetByCode(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.userCategory.getByCode", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//用户自定义类目全量查询
	public function erpUserCategoryQueryAll(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.userCategory.queryAll", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//对接方库批量新增更新接口
	public function erpWarehouseBatchAddUpdate(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.warehouse.batchAddUpdate", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//批量删除外部对接仓库
	public function erpWarehouseBatchDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.warehouse.batchDelete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//对接仓库单条查询接口
	public function erpWarehouseGetByCode(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.warehouse.getByCode", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//对接仓库全量分页查询接口
	public function erpWarehouseQueryAll(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.warehouse.queryAll", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//系统对接库存批量出入增减接口
	public function erpWarehouseStockBatchInOut(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.warehouseStock.batchInOut", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//系统对接库存批量初始化接口
	public function erpWarehouseStockBatchInit(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.warehouseStock.batchInit", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//系统对接库存查询接口
	public function erpWarehouseStockQueryByPwCode(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "erp.warehouseStock.queryByPwCode", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//品牌商捡入
	public function listBrandPickedEnterLeads(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.list.brandPickedEnterLeads", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询零售店详情
	public function listQueryLeadsDetail(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.list.queryLeadsDetail", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//添加零售店
	public function listAddLeads(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.addLeads", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//添加业务员
	public function listAddSalesman(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.addSalesman", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}


	//添加品牌商的业务信息
	public function listAddSpBiz(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.addSpBiz", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//业务员权限关闭
	public function listCancelSalesman(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.cancelSalesman", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询leads冲突
	public function listCheckConflictLeads(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.checkConflictLeads", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询零售店全部类型
	public function listQueryAllLeadsType(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.queryAllLeadsType", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//根据关键字查询零售店
	public function listQueryLeadsBykeyword(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.queryLeadsBykeyword", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//查询品牌商对应的信息
	public function listQuerySpBiz(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.querySpBiz", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	//更新零售店的信息
	public function listUpdateLeads(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.open", "alibaba.lst.updateLeads", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}



	public function ProductTokenlessGet(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.tokenless.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}



	public function ProductTbNicknameToUserId(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.tbNicknameToUserId", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}

	
	public function ProductGroupAdd(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.group.add", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}


	public function ProductGroupGetList(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.group.getList", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}



	public function ProductGroupGet(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.group.get", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}



	public function ProductGroupDelete(APIParam $param) {
		$reqPolicy = new RequestPolicy();
		$reqPolicy->httpMethod="POST";
		$reqPolicy->needAuthorization=true;
		$reqPolicy->requestSendTimestamp=false;
		$reqPolicy->useHttps=false;
		$reqPolicy->useSignture=true;
		$reqPolicy->accessPrivateApi=false;

		$request = new APIRequest ();
		$apiId = new APIId ("com.alibaba.product", "alibaba.product.group.delete", 1);
		$request->apiId = $apiId;

		$request->requestEntity=$param;
		$result = $this->run($reqPolicy,$request);
		return $result;
	}
}