<?php
/**
 * @copyright &copy; 2016 Market Acumen, Inc.
 */
namespace IPBan;

use zesk\Timestamp;
use zesk\Object;

/**
 * 
 * @author kent
 *
 */
class IP extends Object {
	
	/**
	 * Black list IPs are banned/blocked/disallowed
	 *
	 * @var integer
	 */
	const status_blacklist = 0;
	
	/**
	 * White list IPs are allowed always
	 *
	 * @var integer
	 */
	const status_whitelist = 1;
	
	/**
	 *
	 * @param Application $application        	
	 * @param integer $status        	
	 * @param Timestamp $since        	
	 * @return array
	 */
	private static function _list(Application $application, $status, Timestamp $since = null) {
		$query = $application->query_select(__CLASS__)->where("status", $status)->what("*ip", "INET_NTOA(ip)");
		if ($since) {
			$query->where("when|>=", $since);
		}
		return $query->to_array("ip", "ip");
	}
	
	/**
	 *
	 * @param Application $application        	
	 * @param Timestamp $since        	
	 * @return array
	 */
	public static function blacklist(Application $application, Timestamp $since = null) {
		return self::_list(self::status_blacklist, $since);
	}
	/**
	 *
	 * @param Application $application        	
	 * @param Timestamp $since        	
	 * @return array
	 */
	public static function whitelist(Application $application, Timestamp $since = null) {
		return self::_list(self::status_whitelist, $since);
	}
	public static function add(Application $application, $ip, Timestamp $when = null, $status = self::status_whitelist) {
		if ($when === null) {
			$when = Timestamp::now();
		}
		return $application->object_factory(__CLASS__, array(
			"ip" => $ip,
			"when" => $when,
			"status" => $status
		))->store();
	}
	
	/**
	 * Add an IP to the whitelist with the given timestamp
	 *
	 * @param string $ip        	
	 * @param Timestamp $when        	
	 * @return self
	 */
	public static function add_whitelist($ip, Timestamp $when = null) {
		return self::add($ip, $when, self::status_whitelist);
	}
	/**
	 * Add an IP to the blacklist with the given timestamp
	 *
	 * @param string $ip        	
	 * @param Timestamp $when        	
	 * @return self
	 */
	public static function add_blacklist($ip, Timestamp $when = null) {
		return self::add($ip, $when, self::status_blacklist);
	}
}
