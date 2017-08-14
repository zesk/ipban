<?php
/**
 * @copyright &copy; 2016 Market Acumen, Inc.
 */
namespace IPBan;

class Parser_Apache2 extends Parser {
	final function parser() {
		return Parse_Log::factory("httpd", $this->options);
	}
}
