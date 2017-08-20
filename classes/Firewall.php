<?php

namespace IPBan;

use zesk\Application;
use zesk\Model;

abstract class Firewall extends \zesk\Model {
	/**
	 *
	 * @param Application $application        	
	 * @param string $name        	
	 * @return self
	 */
	static final function factory(Application $application, $name) {
		return $application->objects->factory(__CLASS__ . "_" . $name, $application);
	}
	/**
	 * Block an IP address in named list
	 *
	 * @param string $name        	
	 * @param string $ip        	
	 */
	abstract function drop_ip($name, $ip);
	/**
	 * Allow an IP address in named list
	 *
	 * @param string $name        	
	 * @param string $ip        	
	 */
	abstract function allow_ip($name, $ip);
	
	/**
	 * Set an entire IP list at once
	 *
	 * @param string $name        	
	 * @param array $ips        	
	 */
	abstract function set_ips($name, array $ips);
	/**
	 * Fetch a list of IPs by name
	 *
	 * @param string $name        	
	 * @return string[string] ip[ip] array of entries
	 */
	abstract function ip_list($name);
	/**
	 * Does the IP list exist?
	 *
	 * @param string $name        	
	 * @return boolean
	 */
	abstract function has_ip_list($name);
}