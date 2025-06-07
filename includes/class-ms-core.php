<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Core {

    private static $instance = null;
    private $options;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->options = get_option('ms_settings', array());
        $this->ms_init_hooks();
    }

    private function ms_init_hooks() {
        // Schedule cleanup tasks
        if (!wp_next_scheduled('ms_cleanup_login_attempts')) {
            wp_schedule_event(time(), 'daily', 'ms_cleanup_login_attempts');
        }

        if (!wp_next_scheduled('ms_security_scan')) {
            wp_schedule_event(time(), 'twicedaily', 'ms_security_scan');
        }

        add_action('ms_cleanup_login_attempts', array($this, 'ms_cleanup_old_attempts'));
        add_action('ms_security_scan', array($this, 'ms_run_security_scan'));
    }

    public function ms_get_option($key, $default = '') {
        return isset($this->options[$key]) ? $this->options[$key] : $default;
    }

    public function ms_update_option($key, $value) {
        $this->options[$key] = $value;
        update_option('ms_settings', $this->options);
    }

    public function ms_cleanup_old_attempts() {
        global $wpdb;

        $options = get_option('ms_settings', array());
        $max_logs = isset($options['max_logs']) ? min(absint($options['max_logs']), 10000) : 1000;
        $max_days = isset($options['max_days_retention']) ? min(absint($options['max_days_retention']), 365) : 30;

        $table_name = $wpdb->prefix . 'ms_login_attempts';
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $table_name WHERE last_attempt < %s",
            date('Y-m-d H:i:s', strtotime('-' . $max_days . ' days'))
        ));

        $log_table = $wpdb->prefix . 'ms_security_log';
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $log_table WHERE created_at < %s",
            date('Y-m-d H:i:s', strtotime('-' . $max_days . ' days'))
        ));

        // Limit total logs to max_logs
        $total_logs = $wpdb->get_var("SELECT COUNT(*) FROM $log_table");
        if ($total_logs > $max_logs) {
            $offset = $total_logs - $max_logs;
            $wpdb->query("DELETE FROM $log_table ORDER BY created_at ASC LIMIT $offset");
        }
    }

    public function ms_run_security_scan() {
        // Basic security scan
        $this->ms_scan_core_files();
        $this->ms_check_user_permissions();
        $this->ms_scan_plugins_themes();
    }

    private function ms_scan_core_files() {
        // Check for suspicious files in wp-content
        $suspicious_files = array('.php', '.js', '.html');
        $upload_dir = wp_upload_dir();

        if (is_dir($upload_dir['basedir'])) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($upload_dir['basedir'])
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $extension = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                    if (in_array('.' . $extension, $suspicious_files)) {
                        $this->ms_log_security_event('suspicious_file',
                            'Suspicious file detected: ' . $file->getPathname(),
                            'medium'
                        );
                    }
                }
            }
        }
    }

    private function ms_check_user_permissions() {
        // Check for users with admin privileges
        $users = get_users(array('role' => 'administrator'));
        if (count($users) > 5) {
            $this->ms_log_security_event('too_many_admins',
                'Too many administrator users detected: ' . count($users),
                'medium'
            );
        }
    }

    private function ms_scan_plugins_themes() {
        // Check for outdated plugins and themes
        $plugins = get_plugins();
        $updates = get_site_transient('update_plugins');

        if (isset($updates->response)) {
            foreach ($updates->response as $plugin => $data) {
                $this->ms_log_security_event('outdated_plugin',
                    'Outdated plugin detected: ' . $plugin,
                    'low'
                );
            }
        }
    }

    public function ms_log_security_event($event_type, $description, $severity = 'medium', $user_id = null, $country = null, $path = null) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'ms_security_log';

        // Get country if not provided and geolocation is enabled
        if (!$country && $this->ms_get_option('enable_geolocation', 1)) {
            $country = $this->ms_get_country_from_ip();
        }

        // Get current path if not provided
        if (!$path) {
            $path = $_SERVER['REQUEST_URI'] ?? '';
        }

        $wpdb->insert(
            $table_name,
            array(
                'event_type' => sanitize_text_field($event_type),
                'ip_address' => $this->ms_get_user_ip(),
                'user_id' => $user_id,
                'description' => sanitize_text_field($description),
                'severity' => sanitize_text_field($severity),
                'country' => sanitize_text_field($country),
                'path' => sanitize_text_field($path),
                'user_agent' => sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? ''),
                'created_at' => current_time('mysql')
            )
        );
    }

    public function ms_get_country_from_ip($ip = null) {
        if (!$ip) {
            $ip = $this->ms_get_user_ip();
        }

        // Simple country detection using CloudFlare headers
        if (isset($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            return strtoupper($_SERVER['HTTP_CF_IPCOUNTRY']);
        }

        // Fallback to free IP geolocation service
        $response = wp_remote_get("http://ip-api.com/json/{$ip}?fields=countryCode", array(
            'timeout' => 5,
            'user-agent' => 'Morden Security Plugin'
        ));

        if (!is_wp_error($response)) {
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            if (isset($data['countryCode'])) {
                return strtoupper($data['countryCode']);
            }
        }

        return 'Unknown';
    }

    public function ms_get_user_ip() {
        $ip_keys = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );

        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    public function ms_is_ip_blocked($ip = null) {
        if (!$ip) {
            $ip = $this->ms_get_user_ip();
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'ms_blocked_ips';

        $blocked = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table_name WHERE ip_address = %s AND (permanent = 1 OR blocked_until > %s)",
            $ip,
            current_time('mysql')
        ));

        return !empty($blocked);
    }

    public function ms_block_ip($ip, $reason, $duration = null, $permanent = false) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'ms_blocked_ips';
        $blocked_until = $permanent ? null : date('Y-m-d H:i:s', time() + ($duration ?: 3600));

        $wpdb->replace(
            $table_name,
            array(
                'ip_address' => $ip,
                'reason' => $reason,
                'blocked_until' => $blocked_until,
                'permanent' => $permanent ? 1 : 0,
                'created_at' => current_time('mysql')
            )
        );

        $this->ms_log_security_event('ip_blocked', "IP blocked: $ip - Reason: $reason", 'high');
    }
}
