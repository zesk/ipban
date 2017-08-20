<?php

/**
 * iptables interface
 *
 * @author kent
 * @package zesk
 * @subpackage IPBan
 * @copyright &copy; 2017 Market Acumen, Inc.
 */
namespace IPBan;

use zesk\IPv4;

class Firewall_iptables extends Firewall {
	
	/**
	 * Debugging on or off
	 *
	 * @var boolean
	 */
	protected $debug = null;
	
	/**
	 *
	 * @var zesk\Interface_Process
	 */
	protected $proc = null;
	
	/**
	 * iptables command path
	 *
	 * @var string
	 */
	protected $iptables = null;
	
	/**
	 * Chains structure
	 *
	 * @var array
	 */
	protected $chains = array();
	
	/**
	 * IP address => IP address
	 *
	 * @var array
	 */
	protected $whitelist = array();
	
	/**
	 * Whitelist mod time
	 *
	 * @var integer
	 */
	protected $whitelist_file_mtime = null;
	
	/**
	 * IP address => array($chain_path => $rule, $chain_path => $rule)
	 *
	 * @var unknown
	 */
	protected $ips = array();
	
	/**
	 * Chains structure
	 *
	 * @var boolean
	 */
	protected $chains_dirty = true;
	
	/**
	 * Standard chain configuration
	 *
	 * @var unknown
	 */
	static $chain_config = array(
		'INPUT' => array(
			'suffix' => '-input',
			'ip_column' => 'source',
			'command_parameter' => '-s'
		),
		'OUTPUT' => array(
			'suffix' => '-output',
			'ip_column' => 'destination',
			'command_parameter' => '-d'
		)
	);
	
	/**
	 *
	 * @var \zesk\Logger\
	 */
	private $logger = null;
	
	/**
	 * Initialize the chains, setup our internal chains
	 */
	function construct() {
		$this->inherit_global_options();
		$this->logger = $this->application->logger;
		$this->debug = $this->option_bool('debug');
		if ($this->debug) {
			$this->logger->debug("{class} debugging enabled", array(
				"class" => __CLASS__
			));
		}
		$this->iptables = zesk()->paths->which("iptables");
		$this->clean();
		$this->logger->notice("Existing chains: " . implode(", ", array_keys($this->chains)));
		foreach (array(
			Application::chain_toxic,
			Application::chain_ban
		) as $prefix) {
			foreach (self::$chain_config as $parent => $data) {
				$name = $prefix . $data['suffix'];
				if (!$this->has_chain($name)) {
					$this->logger->notice("Adding chain {name}", compact("name"));
					$this->iptables('--new {0}', $name);
				}
				if (!$this->chain_links_to($parent, $name)) {
					$this->logger->notice("Linking chain {name} to chain {parent}", compact("name", "parent"));
					$this->iptables('--insert {0} 1 -j {1}', $parent, $name);
				}
			}
		}
	}
	
	/**
	 * Retrieve all IPs associated with a chain
	 *
	 * @param string $name        	
	 * @return array
	 */
	protected function ip_list($prefix) {
		$ips = array();
		foreach (self::$chain_config as $settings) {
			$suffix = $ip_column = null;
			extract($settings, EXTR_IF_EXISTS);
			$rules = apath($this->chains, array(
				$prefix . $suffix,
				"rules"
			));
			if (!is_array($rules)) {
				continue;
			}
			foreach ($rules as $rule) {
				$ip = $rule[$ip_column];
				$ips[$ip] = $ip;
			}
		}
		return $ips;
	}
	
	/**
	 * Does this chain exist?
	 *
	 * @param string $name        	
	 * @return boolean
	 */
	protected function has_ip_list($name) {
		return array_key_exists($name, $this->chains);
	}
	
	/**
	 * Does the $from chain have a link to the $to chain?
	 *
	 * @param string $from        	
	 * @param string $to        	
	 * @return boolean
	 */
	protected function chain_links_to($from, $to) {
		$chain = apath($this->chains, array(
			$from,
			"rules"
		), array());
		foreach ($chain as $rule_number => $rule) {
			$target = avalue($rule, 'target');
			if ($target === $to) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Find IP addresses in current rules
	 *
	 * @param array $ips        	
	 * @return array
	 */
	protected function find_ips(array $ips) {
		$found = array();
		foreach ($ips as $ip) {
			if (self::null_ip($ip)) {
				continue;
			}
			$rules = avalue($this->ips, $ip);
			if (!$rules) {
				if (!IPv4::is_mask($ip) && !IPv4::valid($ip)) {
					$this->logger->error("Strange IP address: {ip}", array(
						"ip" => $ip
					));
				}
				continue;
			}
			$found = array_merge($found, array_values($rules));
		}
		return $found;
	}
	
	/**
	 * Does the named chain contain the IP address already?
	 *
	 * @param string $name
	 *        	FULL chain name (not prefix)
	 * @param string $ip
	 *        	IP address
	 * @return boolean
	 */
	protected function chain_has_ip($name, $ip) {
		$records = avalue($this->ips, $ip);
		if (!is_array($records)) {
			return false;
		}
		$keys = array_keys($records);
		foreach ($keys as $key) {
			if (begins($key, "$name.")) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Add an IP to the blocked IP list specified by prefix
	 *
	 * @param unknown $prefix        	
	 * @param array $ips        	
	 */
	public function drop_ip($prefix, array $ips) {
		if (count($ips) === 0) {
			return 0;
		}
		//$this->logger->notice("DROPPING {ips}", array("ips" => $ips));
		$this->clean();
		
		$added = 0;
		foreach (self::$chain_config as $chain => $settings) {
			$suffix = $command_parameter = null;
			extract($settings, EXTR_IF_EXISTS);
			$name = $prefix . $suffix;
			foreach ($ips as $ip) {
				if ($this->chain_has_ip($name, $ip)) {
					continue;
				}
				$this->logger->notice("Blocking {ip} in {name}", array(
					"ip" => $ip,
					"name" => $chain
				));
				$this->iptables("-A {0} $command_parameter {1} -j DROP", $name, $ip);
				$added = $added + 1;
			}
		}
		
		$this->chains_dirty = true;
		return $added;
	}
	
	/**
	 * Remove IPs from named filter prefix (should be self::chain_FOO)
	 *
	 * @param string $prefix
	 *        	One of self::chain_FOO
	 * @param array $ips
	 *        	Array of IPs to allow
	 */
	public function allow_ip($prefix, array $ips) {
		if (count($ips) === 0) {
			return 0;
		}
		$this->clean();
		$found = $this->find_ips($ips);
		if (count($found) === 0) {
			$this->logger->debug("No entries found for ips: {ips}", array(
				"ips" => implode(", ", $ips)
			));
			return 0;
		}
		$indexes = array();
		foreach ($found as $k => $rule) {
			$indexes[$k] = $rule['index'];
		}
		array_multisort($indexes, SORT_DESC | SORT_NUMERIC, $found);
		foreach ($found as $rule) {
			$this->logger->notice("Removing index {index} from {name} {source}->{destination}", $rule);
			$this->iptables('-D {0} {1}', $rule['name'], $rule['index']);
			$this->chains_dirty = true;
		}
		return count($found);
	}
	
	/**
	 * Synchronize an IP list with a chain pair
	 *
	 * @param unknown $prefix        	
	 * @param array $ips        	
	 */
	protected function set_ips($prefix, array $ips) {
		$this->clean();
		$this->remove_duplicates($prefix);
		$this->clean();
		
		$chain_ips = $this->ip_list($prefix);
		
		$drop_ips = array();
		$allow_ips = array();
		
		if ($this->debug) {
			$this->logger->debug("IP list: {ips}", array(
				"ips" => _dump($ips)
			));
			$this->logger->debug("CHAIN IPs: {ips}", array(
				"ips" => _dump($chain_ips)
			));
		}
		foreach ($ips as $ip) {
			if (!array_key_exists($ip, $chain_ips)) {
				$drop_ips[] = $ip;
			}
			if (array_key_exists($ip, $chain_ips)) {
				unset($chain_ips[$ip]);
			}
		}
		if ($this->debug) {
			$this->logger->debug("ALLOW IPs: {ips}", array(
				"ips" => _dump($chain_ips)
			));
			$this->logger->debug("DROP IPs: {ips}", array(
				"ips" => _dump($drop_ips)
			));
		}
		$this->allow_ip($prefix, $chain_ips);
		$this->drop_ip($prefix, $drop_ips);
	}
	
	/**
	 * Remove duplicate IPs from list - this happens during development, so might as well keep it
	 * robust
	 *
	 * @param string $prefix        	
	 */
	protected function remove_duplicates($prefix) {
		foreach (self::$chain_config as $settings) {
			$suffix = $ip_column = null;
			extract($settings, EXTR_IF_EXISTS);
			$name = $prefix . $suffix;
			
			$rules = apath($this->chains, array(
				$name,
				"rules"
			));
			if (!is_array($rules)) {
				$this->logger->debug("remove_duplicates: No rules for {name}", compact("name"));
				continue;
			}
			$remove_indexes = array();
			$found_ips = array();
			foreach ($rules as $rule) {
				$ip = $rule[$ip_column];
				if (array_key_exists($ip, $found_ips)) {
					$remove_indexes[$rule['index']] = $ip;
				} else {
					$found_ips[$ip] = $ip;
				}
			}
			if (count($remove_indexes) > 0) {
				krsort($remove_indexes, SORT_NUMERIC | SORT_DESC);
				foreach ($remove_indexes as $index => $ip) {
					$this->logger->debug("Removing duplicate IP {ip} at index {index}", compact("ip", "index"));
					$this->iptables("-D {0} {1}", $name, $index);
				}
				$this->chains_dirty = true;
			}
		}
	}
	
	/**
	 * Clean the chains database from the iptables command
	 */
	protected function clean() {
		if ($this->chains_dirty) {
			$this->logger->debug("Cleaning");
			$this->chains = $this->list_chains();
			$this->ips = $this->ip_index($this->chains);
			$this->chains_dirty = false;
		}
	}
	
	/**
	 * Is this an empty IP address (or all)
	 *
	 * @param string $ip        	
	 * @return boolean
	 */
	private static function null_ip($ip) {
		return begins($ip, '0.0.0.0') || empty($ip);
	}
	
	/**
	 * Compute index by IP address, ignoring null IPs
	 *
	 * @param array $chains        	
	 * @return array
	 */
	private function ip_index(array $chains) {
		$ips = array();
		foreach ($chains as $name => $group) {
			$rules = $group['rules'];
			foreach ($rules as $index => $rule) {
				foreach (to_list("source;destination") as $k) {
					$ip = avalue($rule, $k);
					if (!self::null_ip($ip)) {
						$ips[$ip]["$name.rules.$index.$k"] = $rule;
					}
				}
			}
		}
		return $ips;
	}
	
	/**
	 * Get chains and parse them from the command iptables --list -n -v
	 *
	 * @return array
	 */
	protected function list_chains() {
		$result = $this->iptables("--list -n -v");
		return self::parse_list_chains($result);
	}
	
	/**
	 * Parse parenthesized chain line:
	 *
	 * <code>
	 * (policy ACCEPT)
	 * (policy ACCEPT 4555K packets, 1390M bytes)
	 * (1 references)
	 * </code>
	 *
	 * etc.
	 *
	 * @param string $string        	
	 * @return array
	 */
	protected function parse_chain_parens($string) {
		$matches = null;
		if (preg_match('/([0-9]+) references/', $string, $matches)) {
			return array(
				'references' => intval($matches[1]),
				'user' => true
			);
		}
		if (preg_match('/policy ([A-Za-z]+)(.*)/', $string, $matches)) {
			return array(
				'policy' => $matches[1],
				'user' => false,
				'stats' => trim($matches[2])
			);
		}
		$this->logger->warning("Unable to parse chain parens: {string}", array(
			"string" => $string
		));
		return array();
	}
	
	/**
	 * Parse --list -n output from iptables
	 *
	 * @param array $result        	
	 * @return array
	 */
	protected function parse_list_chains(array $result) {
		$chains = array();
		while (count($result) > 0) {
			$line = array_shift($result);
			if (preg_match('/Chain ([-A-Za-z0-9_]+) \(([^)]*)\)/', $line, $matches)) {
				$name = $matches[1];
				$chain_data = $this->parse_chain_parens($matches[2]);
				$line = array_shift($result);
				$headers = explode(" ", preg_replace('/\s+/', ' ', trim($line)));
				$rules = array();
				$rule_index = 1;
				while (count($result) > 0) {
					$line = trim(array_shift($result));
					if (empty($line)) {
						break;
					}
					$rule = array();
					$columns = explode(" ", preg_replace('/\s+/', ' ', $line));
					foreach ($columns as $index => $column) {
						$rule[$headers[$index]] = $column;
					}
					$rules[$rule_index] = $rule + array(
						'index' => $rule_index,
						'name' => $name
					);
					$rule_index++;
				}
				$chains[$name] = array(
					'rules' => $rules,
					'name' => $name
				) + $chain_data;
			} else {
				$this->logger->notice("Skipping line {line} - no chain match", array(
					"line" => $line
				));
			}
		}
		return $chains;
	}
	
	/**
	 * Run iptables command and return output
	 *
	 * @param string $parameters        	
	 * @return array
	 */
	protected function iptables($parameters) {
		$args = func_get_args();
		array_shift($args);
		return $this->process->execute_arguments($this->iptables . " " . $parameters, $args);
	}
}

