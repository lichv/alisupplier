<?php
namespace Alisupplier\Core\Policy;

class ClientPolicy {
	var $serverHost;
	var $httpPort = 80;
	var $httpsPort = 443;
	var $appKey;
	var $secKey;
	var $defaultContentCharset = "UTF-8";
	var $redirect_uri;
}