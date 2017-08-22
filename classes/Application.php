<?php

/**
 * @copyright &copy; 2016 Market Acumen, Inc.
 */
namespace IPBan;

use zesk\Timestamp;
use zesk\arr;
use zesk\URL;
use zesk\File;
use zesk\Text;
use zesk\Exception_Configuration;
use zesk\JSON;
use zesk\str;
use zesk\IPv4;
use zesk\Process_Mock;
use zesk\FIFO;
use zesk\Net_Sync;
use zesk\Exception_Class_NotFound;
use zesk\Exception_Unsupported;

/**
 * IP Banning application
 *
 * Actively bans misbehaving IPs
 *
 * @author kent
 * @package zesk
 * @subpackage IPBan
 * @copyright (C) 2013 Market Acumen, Inc.
 */
class Application extends \zesk\Application {
	
	/**
	 * String to match in 2016 or earlier installations
	 *
	 * @var string
	 */
	const snippet_match2016 = '/var/db/ipban/ipban.inc';
	
	/**
	 * Current string
	 *
	 * @var string
	 */
	const snippet_match = '/var/db/ipban/ipban.php';
	
	/**
	 *
	 * @var string
	 */
	const snippet = "if (file_exists('/var/db/ipban/ipban.php')) {\n\trequire_once '/var/db/ipban/ipban.php';\n}\n";
	
	/**
	 * Debugging logging enabled
	 *
	 * @var boolean
	 */
	public $debug = false;
	
	/**
	 *
	 * @var FIFO
	 */
	protected $fifo = null;
	
	/**
	 * iptables command path
	 *
	 * @var string
	 */
	protected $iptables = null;
	
	/**
	 * Name for Toxic IPs (from outside source)
	 *
	 * @var string
	 */
	const chain_toxic = 'zesk-ipban-toxic';
	
	/**
	 * Name for dynamically updated IPs
	 *
	 * @var string
	 */
	const chain_ban = 'zesk-ipban';
	
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
	 *
	 * @var Firewall
	 */
	protected $firewall = null;
	
	/**
	 *
	 * @var FS
	 */
	protected $ipban_fs = null;
	public static function default_configuration() {
		return array(
			'zesk\\Module_Logger_File::defaults::time_zone' => 'UTC',
			'zesk\\Module_Logger_File::files::main::linkname' => 'ipban.log',
			'zesk\\Module_Logger_File::files::main::name' => '/var/log/ipban/{YYYY}-{MM}-{DD}-ipban.log',
			'IPBan\\FS::path' => '/var/db/ipban',
			'zesk\\Database::names::default' => "mysqli://ipban:ipban@localhost/ipban",
			'zesk\\Database::default' => "default"
		);
	}
	protected $register_hooks = array(
		'zesk\\Settings'
	);
	protected $load_modules = array(
		'Parse_Log',
		'Server',
		'MySQL',
		'Cron'
	);
	
	/**
	 * Application::preconfigure
	 *
	 * @param array $options        	
	 */
	public function preconfigure(array $options) {
		date_default_timezone_set("UTC");
		umask(0);
		$path = $options['path'] = '/etc/ipban/';
		$file = $options['file'] = 'ipban.json';
		if (is_dir($path)) {
			$conf = path($path, $file);
			if (!is_file($conf)) {
				if (!@file_put_contents($conf, JSON::encode_pretty(self::default_configuration()))) {
					$this->logger->warning("Can not write {conf}", compact("conf"));
					$this->configuration->paths_set(self::default_configuration());
				}
			}
		} else {
			$this->logger->warning("No configuration directory {path} or {file}", compact("path", "file"));
		}
		$path = 'IPBan\\Application::url_toxic_ip';
		if (!$this->configuration->path_exists($path)) {
			$this->configuration->path_set($path, 'http://www.stopforumspam.com/downloads/toxic_ip_cidr.txt');
		}
		return $options;
	}
	
	/**
	 *
	 * {@inheritdoc}
	 *
	 * @see \zesk\Application::postconfigure()
	 */
	public function postconfigure() {
		$type = $this->option("firewall_type", "iptables");
		try {
			$this->firewall = Firewall::firewall_factory($this, $type);
		} catch (Exception_Unsupported $e) {
			$this->logger->warning("Firewall type {type} not supported, no firewall configured", array(
				"type" => $type
			));
		} catch (Exception_Class_NotFound $e) {
			$this->logger->warning("Firewall type {type} not found, no firewall configured", array(
				"type" => $type
			));
		}
		try {
			$this->ipban_fs = new FS($this);
		} catch (Exception_Configuration $e) {
			$this->logger->notice("IPBan\\FS not configured. {e}", array(
				"e" => $e
			));
		}
	}
	/**
	 * Construct the object
	 */
	protected function hook_construct() {
		$this->inherit_global_options();
		$this->debug = $this->option_bool('debug');
		if ($this->debug) {
			$this->logger->debug("{class} debugging enabled", array(
				"class" => __CLASS__
			));
		}
	}
	
	/**
	 * Load an IP file
	 *
	 * @param string $path        	
	 * @param string $purpose        	
	 * @return array
	 */
	private function load_ip_file($path, $purpose = "IP") {
		$this->logger->notice("Loading {purpose} file: {path}", compact("path", "purpose"));
		$contents = File::contents($path, "");
		$contents = Text::remove_line_comments($contents, "#", false);
		$lines = arr::trim_clean(explode("\n", $contents));
		$ips = $this->normalize_ips($lines, $purpose);
		return $ips;
	}
	
	/**
	 * Strip bad IPs and masks from the file
	 *
	 * @param array $ips        	
	 * @return Ambigous <unknown, string>
	 */
	private function normalize_ips(array $ips, $purpose = null) {
		foreach ($ips as $index => $ip) {
			if (IPv4::is_mask($ip)) {
				$ips[$index] = str::unsuffix($ip, "/32");
			} else if (!IPv4::valid($ip)) {
				unset($ips[$index]);
				$this->logger->debug("normalize_ips: Removed {ip} from {purpose}", compact("ip", "purpose"));
			}
		}
		return $ips;
	}
	
	/**
	 * File containing toxic IPs
	 *
	 * @return string
	 */
	public function toxic_ip_path() {
		return $this->option('toxic_ip_path', '/etc/ipban/toxic_ip');
	}
	
	/**
	 * File containing whitelist IPs (never ban)
	 *
	 * @return string
	 */
	public function whitelist_ip_path() {
		return $this->option('whitelist_ip_path', '/etc/ipban/whitelist');
	}
	
	/**
	 * File containing blacklist IPs (always ban)
	 *
	 * @return string
	 */
	public function blacklist_ip_path() {
		return $this->option('blacklist_ip_path', '/etc/ipban/blacklist');
	}
	
	/**
	 * hook_classes
	 *
	 * @param array $classes        	
	 * @return string
	 */
	protected function hook_classes(array $classes) {
		$classes[] = __NAMESPACE__ . "\\" . "Complaint";
		$classes[] = __NAMESPACE__ . "\\" . "Event";
		$classes[] = __NAMESPACE__ . "\\" . "IP";
		$classes[] = __NAMESPACE__ . "\\" . "Parser";
		$classes[] = __NAMESPACE__ . "\\" . "Tag";
//		$classes[] = __NAMESPACE__ . "\\" . "Trigger";
		$classes[] = "zesk\\Settings";
		return $classes;
	}
	
	/**
	 * Implement Application::daemon()
	 *
	 * @param zesk\Interface_Process $p        	
	 * @return string number
	 */
	public static function daemon(zesk\Interface_Process $p) {
		try {
			self::check_permissions();
		} catch (Exception $e) {
			$p->log($e->getMessage());
			return "down";
		}
		$application = self::instance();
		/* @var $application Application_IPBan */
		return $application->daemon_loop($p);
	}
	
	/**
	 * Run cron on a daily basis
	 */
	public static function cron_day() {
		/* @var $app Application_IPBan */
		$app = self::instance();
		$app->sync_toxic_ips();
	}
	
	/**
	 * Run cron on a hourly basis
	 */
	public static function cron_hour() {
		/* @var $app Application_IPBan */
		$app = self::instance();
		$app->check_instrumented_files();
	}
	
	/**
	 * Test Daemon
	 *
	 * @param number $nseconds        	
	 * @return string
	 */
	public static function test($nseconds = 60) {
		$p = new Process_Mock(array(
			"quit_after" => $nseconds
		));
		return self::daemon($p);
	}
	
	/**
	 * Scan and make sure IPban is instrumented on files in the system.
	 *
	 * Useful for detecting/fixing issues with self-updating software
	 *
	 * Set in your configuration file:
	 *
	 * Application_Complaint::ipban_files=["/path/to/index.php","/path/to/wordpress/index.php","/path/to/drupal/index.php"]
	 */
	public function check_instrumented_files() {
		$files = $this->option_list("ipban_files");
		
		if (count($files) === 0) {
			$this->logger->notice("No ipban_file specified for instrumentation.");
		}
		$checked = $updated = $failed = 0;
		foreach ($files as $file) {
			$params = array(
				"class" => get_class($this),
				"file" => $file
			);
			$checked++;
			if (!is_readable($file)) {
				$this->logger->warning("{class}::check_instrumented_files {file} does not exist or is not readable", $params);
				++$failed;
			} else {
				$contents = file_get_contents($file);
				if (strpos($contents, self::snippet_match) !== false) {
					$this->logger->debug("{class}::check_instrumented_files {file} is instrumented", $params);
				} else {
					$found = null;
					foreach (array(
						'<?php',
						'<?'
					) as $tag) {
						if (strpos($contents, $tag) !== false) {
							$found = $tag;
							break;
						}
					}
					if (!$found) {
						$this->logger->error("{class}::check_instrumented_files {file} is not writable", array(
							"class" => get_class($this),
							"file" => $file
						));
					} else {
						if (!is_writable($file)) {
							$this->logger->error("{class}::check_instrumented_files {file} is not writable", $params);
							++$failed;
						} else {
							$contents = implode($tag . "\n" . self::snippet, explode($tag, $contents, 2));
							file_put_contents($file, $contents);
							$this->logger->notice("{class}::check_instrumented_files {file} was updated with ipban snippet", $params);
							$updated++;
						}
					}
				}
			}
		}
		$this->logger->notice("{class}::check_instrumented_files - {checked} checked, {updated} updated, {failed} failed", array(
			"class" => get_class($this),
			"checked" => $checked,
			"failed" => $failed,
			"updated" => $updated
		));
	}
	public function sync_whitelist() {
		$whitelist_file = $this->whitelist_ip_path();
		if (!is_file($whitelist_file)) {
			return null;
		}
		clearstatcache(true, $whitelist_file);
		$mtime = filemtime($whitelist_file);
		if ($mtime !== $this->whitelist_file_mtime) {
			$this->whitelist = arr::flip_copy($this->load_ip_file($whitelist_file, "whitelist"));
			$this->whitelist_file_mtime = $mtime;
			if (count($this->whitelist)) {
				$this->logger->notice("Whitelisted IPs: {ips}", array(
					"ips" => implode(", ", $this->whitelist)
				));
			}
			return true;
		}
		return false;
	}
	/**
	 * Main daemon loop
	 *
	 * @param zesk\Interface_Process $p        	
	 * @return number
	 */
	public function daemon_loop(zesk\Interface_Process $p) {
		$seconds = $this->option("daemon_loop_sleep", 1);
		$this->logger->notice("Daemon loop sleep seconds: {seconds}", array(
			"seconds" => $seconds
		));
		declare(ticks = 1) {
			if (!$this->option_bool("no_fifo")) {
				$this->fifo = self::fifo(true);
				$this->logger->debug("Created fifo {path}", array(
					"path" => $this->fifo->path()
				));
			}
			$this->proc = $p;
			$this->init_firewall();
			$this->sync_toxic_ips(true);
			$this->sync_whitelist();
			$this->initial_ban();
			$this->logger->debug("Entering main loop ...");
			while (!$this->proc->done()) {
				$this->handle_fifo();
				$this->handle_db();
				$this->proc->sleep($seconds);
				$this->sync_toxic_ips();
				$this->sync_whitelist();
			}
		}
		return 0;
	}
	private function initial_ban() {
		$this->last_check = Timestamp::now();
		$ips = Complaint::ban_since(null, $this->option());
		$this->drop_ip(self::chain_ban, $ips);
	}
	/**
	 * Do basic sanity checks prior to launching daemon completely.
	 *
	 * @throws Exception_Configuration
	 */
	private static function check_permissions() {
		global $zesk;
		/* @var $zesk \zesk\Kernel */
		if (($iptables = $zesk->paths->which("iptables")) === null) {
			throw new Exception_Configuration("path", "IP tables is not installed in {path}", array(
				"path" => implode(":", $zesk->paths->command())
			));
		}
		try {
			$this->process->execute("$iptables --list=INPUT -n");
		} catch (\zesk\Exception_Command $e) {
			throw new Exception_Configuration("user", "You must be root to run Application_IPBan");
		}
	}
	
	/**
	 * Retrieve the FIFO to communicate with the server
	 *
	 * @return FIFO
	 */
	public static function fifo($create = false) {
		$configuration = zesk()->configuration->pave("Application_IPBan");
		$path = $configuration->get('fifo_path', 'ipban.fifo');
		$mode = $configuration->get('fifo_mode', 0666);
		return new FIFO($path, $create, $mode);
	}
	
	/**
	 * Receive messages from the FIFO
	 */
	public function handle_fifo() {
		if ($this->option_bool("no_fifo")) {
			return;
		}
		$timeout = $this->option_integer('timeout', 5);
		$result = $this->fifo->read($timeout);
		if ($result === array()) {
			return;
		}
		$this->logger->debug("Received message: {data}", array(
			"data" => serialize($result)
		));
	}
	
	/**
	 * Receive updates from the database
	 */
	public function handle_db() {
		if ($this->option_bool("no_database")) {
			return;
		}
		$this->logger->debug(__CLASS__ . "::handle_db");
		$options = $this->option();
		
		$now = Timestamp::now();
		$ban_ips = Complaint::ban_since($this->last_check, $options);
		$ban_ips += IPBan_IP::blacklist($this->last_check);
		$allow_ips = Complaint::allow_since($this->last_check, $options);
		$allow_ips += IPBan_IP::whitelist($this->last_check) + $this->whitelist;
		
		foreach ($ban_ips as $ip => $ip) {
			if (array_key_exists($ip, $allow_ips)) {
				unset($ban_ips[$ip]);
			}
		}
		if ($this->last_check === null) {
			$this->sync_ip_list(self::chain_ban, $ban_ips);
		} else {
			$this->drop_ip(self::chain_ban, $ban_ips);
			$this->allow_ip(self::chain_ban, $allow_ips);
		}
		$this->last_check = $now;
		// 		var_dump("ban_ips", $ban_ips);
		// 		var_dump("allow_ips", $allow_ips);
	}
	
	/**
	 * Support whitelisting entire networks
	 *
	 * @param string $network        	
	 * @param array $ips        	
	 * @return array
	 */
	private static function remove_masked_ips($network, array $ips, $purpose = null) {
		foreach ($ips as $key => $ip) {
			if (IPv4::within_network($ip, $network)) {
				$this->logger->debug("Removed {ip} from list - within {purpose} network {network}", compact("ip", "network", "purpose"));
				unset($ips[$key]);
			}
		}
		return $ips;
	}
	
	/**
	 * Filter whitelist
	 *
	 * @param array $ips        	
	 */
	protected function filter_whitelist(array $ips) {
		$ips = arr::flip_copy($ips, false);
		foreach ($this->whitelist as $whiteip) {
			if (IPv4::is_mask($whiteip)) {
				$ips = self::remove_masked_ips($whiteip, $ips, "whitelist");
			} else if (array_key_exists($whiteip, $ips)) {
				unset($ips[$whiteip]);
			}
		}
		return array_values($ips);
	}
	
	/**
	 * Add an IP to the blocked IP list specified by prefix
	 *
	 * @param unknown $prefix        	
	 * @param array $ips        	
	 */
	protected function drop_ip($prefix, array $ips) {
		$ips = $this->filter_whitelist($ips);
		if (count($ips) === 0) {
			return 0;
		}
		//$this->logger->notice("DROPPING {ips}", array("ips" => $ips));
		
		if ($this->ipban_fs) {
			$this->ipban_fs->drop_ip($ips);
		}
		return $this->firewall ? $this->firewall->drop_ip($prefix, $ips) : 0;
	}
	
	/**
	 * Remove IPs from named filter prefix (should be self::chain_FOO)
	 *
	 * @param string $prefix
	 *        	One of self::chain_FOO
	 * @param array $ips
	 *        	Array of IPs to allow
	 */
	protected function allow_ip($prefix, array $ips) {
		if (count($ips) === 0) {
			return 0;
		}
		if ($this->ipban_fs) {
			$this->ipban_fs->allow_ip($ips);
		}
		return $this->firewall ? $this->firewall->allow_ip($prefix, $ips) : 0;
	}
	
	/**
	 * Synchronize the toxic IP list
	 *
	 * @param string $force        	
	 * @return string
	 */
	public function sync_toxic_ips($force = false) {
		static $errored = false;
		$url = $this->option('url_toxic_ip');
		if (!URL::valid($url)) {
			if (!$errored) {
				$this->logger->error("Application_Complaint::url_toxic_ip not set to valid URL: {url}", array(
					"url" => $url
				));
				$errored = true;
			}
			return "config";
		}
		$path = $this->toxic_ip_path();
		$changed = Net_Sync::url_to_file($url, $path);
		if ($changed || $force) {
			if (!is_file($path)) {
				return "no-file";
			}
			$ips = $this->load_ip_file($path, "toxic");
			$this->sync_ip_list(self::chain_toxic, $ips);
			return "synced";
		}
		return "unchanged";
	}
	
	/**
	 * Synchronize an IP list with a chain pair
	 *
	 * @param unknown $prefix        	
	 * @param array $ips        	
	 */
	protected function sync_ip_list($prefix, array $ips) {
		$ips = $this->filter_whitelist($ips);
		if ($this->ipban_fs) {
			$this->ipban_fs->drop($ips);
		}
		if ($this->firewall) {
			$this->firewall->set_ips($prefix, $ips);
		}
	}
}

