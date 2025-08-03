<?php

namespace MordenSecurity\Core;

if (!defined('ABSPATH')) {
    exit;
}

final class SecurityEventTypes
{
    private static array $eventLabels = [
        // WAF & Firewall Events
        'waf_blocked' => 'WAF Block',
        'user_enumeration' => 'User Enumeration',
        'sql_injection' => 'SQL Injection',
        'cross_site_scripting' => 'Cross-Site Scripting (XSS)',
        'directory_traversal' => 'Directory Traversal',
        'local_file_inclusion' => 'Local File Inclusion',
        'remote_file_inclusion' => 'Remote File Inclusion',
        'command_injection' => 'Command Injection',
        'code_execution' => 'Code Execution',
        'suspicious_user_agent' => 'Suspicious User Agent',
        'bad_bot_detected' => 'Bad Bot Detected',

        // IP & Geolocation Events
        'ip_blocked' => 'IP Blocked',
        'ip_whitelisted' => 'IP Whitelisted',
        'country_blocked' => 'Country Blocked',

        // Login & Authentication
        'login_success' => 'Successful Login',
        'login_failed' => 'Failed Login',
        'user_locked_out' => 'User Locked Out',
        'brute_force_attempt' => 'Brute Force Attempt',

        // System & Hardening
        'wp_config_access' => 'wp-config.php Accessed',
        'sensitive_file_access' => 'Sensitive File Accessed',
        'plugin_activated' => 'Plugin Activated',
        'plugin_deactivated' => 'Plugin Deactivated',
        'theme_switched' => 'Theme Switched',
        'settings_changed' => 'Settings Changed',

        // General
        'unknown_event' => 'Unknown Security Event',
    ];

    public static function getLabel(string $eventType): string
    {
        return self::$eventLabels[$eventType] ?? self::getFormattedUnknownLabel($eventType);
    }

    public static function getAllLabels(): array
    {
        return self::$eventLabels;
    }

    public static function isValidEvent(string $eventType): bool
    {
        return isset(self::$eventLabels[$eventType]);
    }

    private static function getFormattedUnknownLabel(string $eventType): string
    {
        return 'Unknown (' . esc_html(str_replace('_', ' ', ucfirst($eventType))) . ')';
    }

    public static function getCategoryForEvent(string $eventType): string
    {
        $categories = [
            'waf' => ['waf_blocked', 'user_enumeration', 'sql_injection', 'cross_site_scripting', 'directory_traversal', 'local_file_inclusion', 'remote_file_inclusion', 'command_injection', 'code_execution', 'suspicious_user_agent', 'bad_bot_detected'],
            'ip' => ['ip_blocked', 'ip_whitelisted', 'country_blocked'],
            'login' => ['login_success', 'login_failed', 'user_locked_out', 'brute_force_attempt'],
            'system' => ['wp_config_access', 'sensitive_file_access', 'plugin_activated', 'plugin_deactivated', 'theme_switched', 'settings_changed'],
        ];

        foreach ($categories as $category => $events) {
            if (in_array($eventType, $events)) {
                return $category;
            }
        }

        return 'general';
    }
}
