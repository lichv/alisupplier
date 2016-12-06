<?php
namespace Alisupplier\Core;

class APIParam {
	private $params;

	public function __construct($array=[]) {
		$this->params = $array;
	}

	public function __call($method,$arguments) {
		if(substr($method, 0,3)=='get'){
			return $this->getValue(substr($method,3,strlen($method)-3));
		}elseif (substr($method,0,3)=='set') {
			return $this->setValue(substr($method,3,strlen($method)-3),$arguments);
		}elseif (method_exists($this, $method)) {
			return $this->$method($arguments);
		}else{
			return false;
		}
	}

	public function getValue($str) {
		$str[0] = strtolower($str[0]);
		$result = in_array($str, array_keys($this->params))?$this->params[$str]:false;
		return $result;
	}

	public function setValue($name,$value) {
		$name[0] = strtolower($name[0]);
		if(count($value)==1){
			$this->params[$name] = current($value);
		}
	}


	public function getSdkStdResult(){
		return $this->params;
	}
}