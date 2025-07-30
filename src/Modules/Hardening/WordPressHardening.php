<?php

namespace MordenSecurity\Modules\Hardening;

if (!defined('ABSPATH')) {
    exit;
}

class WordPressHardening
{
    private array $config;

    public function __construct()
    {
        $this->config = [
            'hide_wp_version' => get_option('ms_hide_wp_version', true),
            'disable_xmlrpc' => get_option('ms_disable_xmlrpc', true),
            'protect_config' => get_option('ms_protect_config', true),
            'restrict_file_edit' => get_option('ms_restrict_file_edit', true),
            'sanitize_headers' => get_option('ms_sanitize_headers', true)
        ];

        $this->initializeHooks();
    }

    private function initializeHooks(): void
    {
        if ($this->config['hide_wp_version']) {
            add_filter('the_generator', '__return_empty_string', 99);
        }

        if ($this->config['disable_xmlrpc']) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', function($headers) {
                unset($headers['X-Pingback']);
                return $headers;
            });
        }

        if ($this->config['restrict_file_edit']) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }

        if ($this->config['sanitize_headers']) {
            add_action('send_headers', [$this, 'sanitizeHeaders'], 99);
        }
    }

    public function protectConfigFiles(): void
    {
        if (!$this->config['protect_config']) {
            return;
        }

        $htaccessPath = ABSPATH . '.htaccess';
        $denyRules = "\n# Morden Security Config Protection\n<Files wp-config.php>\norder allow,deny\ndeny from all\n</Files>\n";

        if (file_exists($htaccessPath) && strpos(file_get_contents($htaccessPath), 'Morden Security Config Protection') === false) {
            file_put_contents($htaccessPath, $denyRules, FILE_APPEND | LOCK_EX);
        }
    }

    public function sanitizeHeaders(): void
    {
        header_remove('X-Powered-By');
        header_remove('Server');
        header('X-Content-Type-Options: nosniff', true);
        header('X-Frame-Options: SAMEORIGIN', true);
        header('X-XSS-Protection: 1; mode=block', true);
        header('Referrer-Policy: no-referrer-when-downgrade', true);
    }
}
