<?php

/**
 * @copyright &copy; 2017 Market Acumen, Inc.
 */
namespace IPBan;

use zesk\Kernel;
use zesk\Hooks;

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
	 * Reset our static global when the application is configured
	 * 
	 * @param Kernel $zesk
	 */
	public static function hooks(Kernel $zesk) {
		$zesk->hooks->add(Hooks::hook_configured, function (Application $application) {
			self::$types = array();
		});
	}
	
	/**
	 *
	 * @param Application $application        	
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
