<?php

/**
 * @copyright &copy; 2017 Market Acumen, Inc.
 */
namespace IPBan;

/**
 *
 * @see Class_Tag
 * @author kent
 */
class Tag extends Object {
	public static function instance(Application $application, $type, $value) {
		return $application->object_factory(__CLASS__, array(
			"type" => Tag_Type::instance($application, $type),
			"value" => $value
		))->register();
	}
}
