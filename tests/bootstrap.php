<?php

define('WP_TESTS_PHPUNIT_POLYFILLS_PATH', __DIR__ . '/../vendor/yoast/phpunit-polyfills/phpunitpolyfills-autoload.php');

$_tests_dir = getenv('WP_TESTS_DIR');
if (!$_tests_dir) {
    $_tests_dir = rtrim(sys_get_temp_dir(), '/\\') . '/wordpress-tests-lib';
}

if (!file_exists($_tests_dir . '/includes/functions.php')) {
    echo "Could not find $_tests_dir/includes/functions.php\n";
    exit(1);
}

require_once $_tests_dir . '/includes/functions.php';

function _manually_load_plugin() {
    require dirname(__DIR__) . '/morden-security.php';
}

tests_add_filter('muplugins_loaded', '_manually_load_plugin');

require $_tests_dir . '/includes/bootstrap.php';

define('MS_TEST_MODE', true);

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/wordpress/');
}

if (!defined('MS_PLUGIN_PATH')) {
    define('MS_PLUGIN_PATH', dirname(__DIR__) . '/');
}

if (!defined('MS_LOGS_DIR')) {
    define('MS_LOGS_DIR', sys_get_temp_dir() . '/ms-logs/');
}

if (!is_dir(MS_LOGS_DIR)) {
    wp_mkdir_p(MS_LOGS_DIR);
}
