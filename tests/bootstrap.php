<?php

define('WP_TESTS_PHPUNIT_POLYFILLS_PATH', __DIR__ . '/../vendor/yoast/phpunit-polyfills/phpunitpolyfills-autoload.php');

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

if (!defined('MS_MIN_PHP_VERSION')) {
    define('MS_MIN_PHP_VERSION', '7.4');
}

if (!defined('MS_PLUGIN_FILE')) {
    define('MS_PLUGIN_FILE', __DIR__ . '/../morden-security.php');
}

if (!defined('MS_PLUGIN_BASENAME')) {
    define('MS_PLUGIN_BASENAME', 'morden-security/morden-security.php');
}

// Mock WordPress functions
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

if (!function_exists('wp_strip_all_tags')) {
    function wp_strip_all_tags($string, $remove_breaks = false) {
        $string = strip_tags($string);
        if ($remove_breaks) {
            $string = preg_replace('/[\r\n\t ]+/', ' ', $string);
        }
        return trim($string);
    }
}

if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str) {
        return trim(stripslashes(strip_tags($str)));
    }
}

if (!function_exists('sanitize_key')) {
    function sanitize_key($key) {
        return preg_replace('/[^a-z0-9_\-]/', '', strtolower($key));
    }
}

if (!function_exists('current_user_can')) {
    function current_user_can($capability) {
        return true;
    }
}

if (!function_exists('wp_nonce_field')) {
    function wp_nonce_field($action = -1, $name = "_wpnonce", $referer = true, $echo = true) {
        return '<input type="hidden" name="' . $name . '" value="test_nonce" />';
    }
}

if (!function_exists('wp_verify_nonce')) {
    function wp_verify_nonce($nonce, $action = -1) {
        return true;
    }
}

// Create logs directory
if (!is_dir(MS_LOGS_DIR)) {
    wp_mkdir_p(MS_LOGS_DIR);
}

// Load composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';
