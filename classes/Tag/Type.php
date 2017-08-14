<?php

/**
 * @copyright &copy; 2017 Market Acumen, Inc.
 */
namespace IPBan;

/**
 *
 * @author kent
 *        
 */
class Tag_Type extends Object {
	/**
	 *
	 * @var array
	 */
	static $types = array();
	
	/**
	 *
	 * @param \zesk\Application $application        	
	 * @param unknown $name        	
	 * @return mixed|number
	 */
	public static function instance(Application $application, $name) {
		$lowname = strtolower($name);
		if (array_key_exists($lowname, self::$types)) {
			return self::$types[$lowname];
		}
		return self::$types[$lowname] = $application->object_factory(__CLASS__, array(
			"name" => $name
		))->register();
	}
}
