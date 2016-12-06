<?php
namespace Alisupplier\Core\Serialize;
interface Serializer{
	public function supportedContentType();
	public function serialize($serializer);
}