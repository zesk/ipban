<?php

/**
 * 
 */
namespace IPBan;

use zesk\Application;
use zesk\Model;

abstract class Firewall extends Model {
	/**
	 *
	 * @param Application $application        	
	 * @param string $name        	
	 * @return self
	 */
	static final function firewall_factory(Application $application, $name) {
		return $application->objects->factory(__CLASS__ . "_" . $name, $application);
	}
	/**
	 * Block an IP address in named list
	 *
	 * @param string $name        	
	 * @param string $ip        	
	 */
	abstract function drop_ip($name, array $ips);
	/**
	 * Allow an IP address in named list
	 *
	 * @param string $name        	
	 * @param string $ip        	
	 */
	abstract function allow_ip($name, array $ip);
	
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