<?php

// Skip WordPress setup for basic unit tests
if (!defined('WP_TESTS_PHPUNIT_POLYFILLS_PATH')) {
    define('WP_TESTS_PHPUNIT_POLYFILLS_PATH', __DIR__ . '/../vendor/yoast/phpunit-polyfills/phpunitpolyfills-autoload.php');
}

// Define WordPress constants for testing
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/../');
}

if (!defined('MS_PLUGIN_PATH')) {
    define('MS_PLUGIN_PATH', __DIR__ . '/../');
}

if (!defined('MS_LOGS_DIR')) {
    define('MS_LOGS_DIR', sys_get_temp_dir() . '/ms-logs/');
}

if (!defined('MS_PLUGIN_VERSION')) {
    define('MS_PLUGIN_VERSION', '1.0.0');
}

// Mock WordPress functions for testing
if (!function_exists('get_option')) {
    function get_option($option, $default = false) {
        return $default;
    }
}

if (!function_exists('update_option')) {
    function update_option($option, $value) {
        return true;
    }
}

if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p($target) {
        return mkdir($target, 0755, true);
    }
}

if (!function_exists('get_current_user_id')) {
    function get_current_user_id() {
        return 1;
    }
}

if (!function_exists('current_user_can')) {
    function current_user_can($capability) {
        return true;
    }
}

if (!function_exists('wp_strip_all_tags')) {
    function wp_strip_all_tags($string, $remove_breaks = false) {
        return trim(strip_tags($string));
    }
}

// Create logs directory
if (!is_dir(MS_LOGS_DIR)) {
    wp_mkdir_p(MS_LOGS_DIR);
}

// Load composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';
