<?php

/**
 * 
 */
namespace IPBan;

/**
 *
 * @author kent
 *        
 */
abstract class Class_Object extends \zesk\Class_Object {
	/**
	 *
	 * @var array
	 */
	protected $options = array(
		"table_prefix" => "IPBan_"
	);
}
