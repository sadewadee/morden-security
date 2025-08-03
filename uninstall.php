<?php

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$delete_data = get_option('ms_delete_data_on_uninstall');

if ($delete_data) {
    $upload_dir = wp_upload_dir();
    $db_path = $upload_dir['basedir'] . '/morden-security/logs/security.db';
    if (file_exists($db_path)) {
        @unlink($db_path);
    }

    $logs_dir = $upload_dir['basedir'] . '/morden-security/logs';
    $main_dir = $upload_dir['basedir'] . '/morden-security';
    if (is_dir($logs_dir)) {
        @rmdir($logs_dir);
    }
    if (is_dir($main_dir)) {
        @rmdir($main_dir);
    }

    global $wpdb;
    $prefix = 'ms_';
    $wpdb->query($wpdb->prepare("DELETE FROM $wpdb->options WHERE option_name LIKE %s", $prefix . '%'));

    $wpdb->query($wpdb->prepare("DELETE FROM $wpdb->options WHERE option_name LIKE %s", '_transient_' . $prefix . '%'));
    $wpdb->query($wpdb->prepare("DELETE FROM $wpdb->options WHERE option_name LIKE %s", '_transient_timeout_' . $prefix . '%'));

    wp_clear_scheduled_hook('morden_security_ruleset_update');
}