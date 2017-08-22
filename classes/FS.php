<?php

/**
 * @copyright &copy; 2016 Market Acumen, Inc.
 */
namespace IPBan;

/**
 */
use zesk\Directory;
use zesk\Options;
use zesk\IPv4;
use zesk\Exception_Configuration;
use zesk\Exception_Directory_Create;

/**
 *
 * @author kent
 *        
 */
class FS extends Options {
	/**
	 *
	 * @var string
	 */
	private $fs_path = null;
	
	/**
	 *
	 * @var Application
	 */
	private $application = null;
	
	/**
	 *
	 * @param array $options        	
	 * @throws Exception_Configuration
	 */
	function __construct(Application $application, array $options = null) {
		parent::__construct($options);
		$this->application = $application;
		$this->inherit_global_options();
		$this->fs_path = $this->option('path');
		if (empty($this->fs_path)) {
			throw new Exception_Configuration("IPBan\\FS::path", "No path set for {class}::path", array(
				"class" => __CLASS__
			));
		}
		Directory::depend($this->fs_path, 0755);
		$this->php_inc_create();
	}
	
	/**
	 *
	 * @param string $ip
	 *        	IP address
	 * @return NULL|string
	 */
	private function ip_path($ip) {
		if (!IPv4::valid($ip) && !IPv4::is_mask($ip)) {
			return null;
		}
		return path($this->fs_path, implode("/", explode(".", $ip)));
	}
	
	/**
	 *
	 * @param string $ip        	
	 * @param string $func        	
	 * @return number of IPs that were
	 */
	private function _ip_drop_allow($ip, $func) {
		if (IPv4::valid($ip)) {
			return $this->$func($ip);
		}
		if (!IPv4::is_mask($ip)) {
			return 0;
		}
		list($low_ip, $nbits) = IPv4::mask_to_integers($ip);
		list($low, $high) = IPv4::network($ip);
		$n = 0;
		if ($nbits > 24) {
			for ($i = $low; $i <= $high; $i++) {
				$n += $this->$func(IPv4::from_integer($i));
			}
		} else {
			$npops = $nbits <= 16 ? 2 : 1;
			$delta = $nbits <= 16 ? 256 * 256 : 256;
			for ($i = $low; $i <= $high; $i += $delta) {
				$ip = IPv4::from_integer($i);
				$ip = explode(".", $ip);
				for ($j = 0; $j < $npops; $j++) {
					array_pop($ip);
				}
				$ip[] = "*";
				$ip = implode(".", $ip);
				if ($this->$func($ip)) {
					$n += $delta;
				}
			}
		}
		return $n;
	}
	
	/**
	 *
	 * @param array $ips
	 *        	Array of IPs to disallow
	 * @param unknown $func        	
	 * @return integer
	 */
	private function _ips_drop_allow($ips, $func) {
		if (is_array($ips)) {
			$n = 0;
			foreach ($ips as $ip) {
				$n += $this->_ip_drop_allow($ip, $func);
			}
			return $n;
		}
		return $this->_ip_drop_allow($ips, $func);
	}
	
	/**
	 * Block (drop) all packets from requested IPs
	 *
	 * @param array $ips
	 *        	List of IPs or IP masks to deny
	 *        	
	 * @return integer
	 */
	function drop($ips) {
		return $this->_ips_drop_allow($ips, "drop_ip");
	}
	
	/**
	 * Allow traffic from requested IPs
	 *
	 * @param array $ips
	 *        	List of IPs or IP masks to allow
	 *        	
	 * @return integer
	 */
	function allow($ips) {
		return $this->_ips_drop_allow($ips, "allow_ip");
	}
	
	/**
	 * Drop Ips passed in
	 *
	 * @param array|string $ips
	 *        	IP or list of IPs to drop
	 *        	
	 * @return integer
	 */
	function drop_ip($ips) {
		if (is_array($ips)) {
			$n = 0;
			foreach ($ips as $ip) {
				$n += $this->drop_ip($ip);
			}
			return $n;
		}
		$ff = $this->ip_path($ips);
		if (!$ff) {
			return 0;
		}
		if (file_exists($ff)) {
			return 1;
		}
		$dir = dirname($ff);
		try {
			Directory::depend($dir, 0755);
			file_put_contents($ff, time());
			chmod($ff, 0644);
			return 1;
		} catch (Exception_Directory_Create $e) {
			$this->application->logger->error("Unable to create directory {dir} to block IP {ips}", array(
				"dir" => $dir,
				"ips" => $ips
			));
		}
		return 0;
	}
	
	/**
	 *
	 * @param unknown $ips        	
	 * @return unknown|number
	 */
	function allow_ip($ips) {
		if (is_array($ips)) {
			$n = 0;
			foreach ($ips as $ip) {
				$n += $this->allow_ip($ip);
			}
			return $n;
		}
		$ff = $this->ip_path($ips);
		if (!$ff) {
			return 0;
		}
		if (file_exists($ff)) {
			unlink($ff);
			return 1;
		}
		return 0;
	}
	
	/**
	 * Clean empty directories
	 *
	 * @return number
	 */
	function clean_empties() {
		$deleted = 0;
		foreach (Directory::ls($this->fs_path, null, true) as $class_a) {
			if (Directory::is_empty($class_a)) {
				Directory::delete($class_a);
				$deleted++;
			}
		}
		return $deleted;
	}
	
	/**
	 * Ensure IPBan global include exists
	 */
	private function php_inc_create() {
		file_put_contents(path($this->fs_path, "ipban.php"), $this->application->theme('ipban-php', array(
			"fs_path" => $this->fs_path
		)));
	}
}
