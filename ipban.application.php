<?php
/**
 * Main IP Ban application entry point
 * 
 * @copyright &copy; 2017 Market Acumen, Inc. All rights reserved.
 */
/* @var $zesk \zesk\Kernel */
if (!file_exists(__DIR__ . "/vendor/autoload.php")) {
	die("Run composer install");
}

require_once __DIR__ . "/vendor/autoload.php";

$zesk = zesk\Kernel::singleton();
$zesk->application_class = 'IPBan\\Application';
$zesk->paths->set_application(__DIR__);
$zesk->autoloader->path(__DIR__ . "/classes", array(
	"lower" => false,
	"class_prefix" => "IPBan\\"
));

$app = $zesk->create_application();
$app->zesk_command_path($app->application_root("command"), "IPBan\\Command_");

return $app->configure();

