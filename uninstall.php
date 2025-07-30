<?php

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

define('MS_UPLOADS_DIR', wp_upload_dir()['basedir'] . '/morden-security/');

function ms_remove_plugin_data()
{
    // A list of all options created by the plugin.
    $optionsToDelete = [
        'ms_version', 'ms_db_version', 'ms_installation_date',
        'ms_security_enabled', 'ms_logging_enabled', 'ms_log_retention_days',
        'ms_notification_email', 'ms_firewall_enabled', 'ms_waf_sensitivity',
        'ms_owasp_rules_enabled', 'ms_custom_rules_enabled', 'ms_bot_detection_enabled',
        'ms_bot_sensitivity', 'ms_good_bot_whitelist', 'ms_bot_challenge_threshold',
        'ms_bot_block_threshold', 'ms_auto_ip_blocking', 'ms_default_block_duration',
        'ms_threat_score_threshold', 'ms_escalation_enabled', 'ms_whitelist_admin_enabled',
        'ms_country_blocking_enabled', 'ms_blocked_countries', 'ms_allowed_countries',
        'ms_country_detection_method', 'ms_login_protection_enabled', 'ms_max_login_attempts',
        'ms_lockout_duration', 'ms_strong_password_required', 'ms_captcha_enabled',
        'ms_cache_enabled', 'ms_cache_duration', 'ms_database_optimization',
        'ms_debug_mode', 'ms_maintenance_mode', 'ms_webhook_enabled',
        'ms_api_access_enabled', 'ms_github_token', 'ms_update_available',
        'ms_last_auto_update', 'ms_custom_waf_rules', 'ms_whitelisted_bots'
    ];

    // Delete all options.
    foreach ($optionsToDelete as $option) {
        delete_option($option);
        delete_site_option($option);
    }

    // Clear all scheduled cron jobs.
    wp_clear_scheduled_hook('ms_cleanup_temp_blocks');
    wp_clear_scheduled_hook('ms_rotate_logs');
    wp_clear_scheduled_hook('ms_update_geo_data');
    wp_clear_scheduled_hook('ms_optimize_database');
    wp_clear_scheduled_hook('ms_check_updates');

    // Remove the database file and directories.
    if (is_dir(MS_UPLOADS_DIR)) {
        ms_remove_directory(MS_UPLOADS_DIR);
    }

    // Flush rewrite rules just in case.
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
