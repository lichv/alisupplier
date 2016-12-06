<?php
namespace Alisupplier\Core\Serialize;

use Alisupplier\Core\Serialize\Json2Deserializer;
use Alisupplier\Core\Serialize\Param2RequestSerializer;
use Alisupplier\Core\Policy\DataProtocol;

class SerializerProvider {
	private static $serializerStore = array ();
	private static $deSerializerStore = array ();
	private static $isInited = false;
	private static function initial() {
		SerializerProvider::$serializerStore [DataProtocol::param2] = new Param2RequestSerializer ();
		SerializerProvider::$deSerializerStore [DataProtocol::json2] = new Json2Deserializer ();
		SerializerProvider::$deSerializerStore [DataProtocol::param2] = new Json2Deserializer ();
		$isInited = true;
	}
	static function getSerializer($key) {
		if (! SerializerProvider::$isInited) {
			SerializerProvider::initial ();
		}
		$result = SerializerProvider::$serializerStore [$key];
		return $result;
	}
	static function getDeSerializer($key) {
		if (! SerializerProvider::$isInited) {
			SerializerProvider::initial ();
		}
		$result = SerializerProvider::$deSerializerStore [$key];
		return $result;
	}
}