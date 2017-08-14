-- Database: mysql
CREATE TABLE `{table}` (
	`ip`			integer unsigned NOT NULL PRIMARY KEY,
	`server`		integer unsigned NOT NULL,
	`created`		timestamp NOT NULL DEFAULT 0,
	`recent`		timestamp NOT NULL DEFAULT 0,
	`complaints`	integer unsigned NOT NULL DEFAULT 0,
	`severity`		tinyint unsigned NOT NULL DEFAULT 0,
	INDEX created (created),
	INDEX complaints (complaints)
);
