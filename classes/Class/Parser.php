<?php
/**
 * @copyright &copy; 2017 Market Acumen, Inc.
 */
namespace IPBan;

/**
 *
 * @see Parser
 * @author kent
 *        
 */
class Class_Parser extends Class_Object {
	
	/**
	 * How do we find these in the database?
	 *
	 * @var string
	 */
	public $id_column = 'id';
	
	/**
	 * Find keys to find duplicates
	 *
	 * @var array
	 */
	public $find_keys = array(
		"server",
		"path"
	);
	
	/**
	 * Polymorphic base class
	 *
	 * @var string
	 */
	public $polymorphic = 'IPBan\\Parser';
	
	/**
	 *
	 * @var array
	 */
	public $has_one = array(
		'server' => 'zesk\\Server'
	);
	
	/**
	 * Column types
	 *
	 * @var array
	 */
	public $column_types = array(
		'id' => self::type_id,
		'server' => self::type_object,
		'path' => self::type_string,
		'handler' => self::type_polymorph,
		'state' => self::type_serialize,
		'modified' => self::type_modified,
		'created' => self::type_created
	);
}
