<?php
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Remove plugin options
delete_option('ms_settings');

// Remove database tables
global $wpdb;

$tables = array(
    $wpdb->prefix . 'ms_login_attempts',
    $wpdb->prefix . 'ms_security_log',
    $wpdb->prefix . 'ms_blocked_ips'
);

foreach ($tables as $table) {
    $wpdb->query("DROP TABLE IF EXISTS $table");
}

// Clear scheduled events
wp_clear_scheduled_hook('ms_cleanup_login_attempts');
wp_clear_scheduled_hook('ms_security_scan');

// Remove .htaccess rules
if (!function_exists('get_home_path')) {
    require_once(ABSPATH . 'wp-admin/includes/file.php');
}

$htaccess_file = get_home_path() . '.htaccess';

if (is_writable($htaccess_file)) {
    $content = file_get_contents($htaccess_file);

    // Remove Morden Security rules
    $content = preg_replace('/\n# BEGIN Morden Security.*?# END Morden Security\n/s', '', $content);

    file_put_contents($htaccess_file, $content);
}