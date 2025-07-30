<?php

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

define('MS_UPLOADS_DIR', wp_upload_dir()['basedir'] . '/morden-security/');

function ms_remove_plugin_data()
{
    global $wpdb;

    $optionsToDelete = [
        'ms_version',
        'ms_db_version',
        'ms_installation_date',
        'ms_firewall_enabled',
        'ms_auto_blocking_enabled',
        'ms_bot_detection_enabled',
        'ms_logging_enabled',
        'ms_github_updates_enabled'
    ];

    foreach ($optionsToDelete as $option) {
        delete_option($option);
        delete_site_option($option);
    }

    wp_clear_scheduled_hook('ms_cleanup_temp_blocks');
    wp_clear_scheduled_hook('ms_rotate_logs');
    wp_clear_scheduled_hook('ms_update_geo_data');
    wp_clear_scheduled_hook('ms_optimize_database');
    wp_clear_scheduled_hook('ms_check_updates');

    if (is_dir(MS_UPLOADS_DIR)) {
        ms_remove_directory(MS_UPLOADS_DIR);
    }

    flush_rewrite_rules();
}

function ms_remove_directory(string $dir): bool
{
    if (!is_dir($dir)) {
        return false;
    }

    $files = array_diff(scandir($dir), ['.', '..']);

    foreach ($files as $file) {
        $path = $dir . DIRECTORY_SEPARATOR . $file;

        if (is_dir($path)) {
            ms_remove_directory($path);
        } else {
            unlink($path);
        }
    }

    return rmdir($dir);
}

ms_remove_plugin_data();
