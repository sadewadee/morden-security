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

        // Schedule integrity check
        if (!wp_next_scheduled('ms_integrity_check')) {
            wp_schedule_event(time(), 'daily', 'ms_integrity_check');
        }

        add_action('ms_cleanup_login_attempts', array($this, 'ms_cleanup_old_attempts'));
        add_action('ms_security_scan', array($this, 'ms_run_security_scan'));
        add_action('ms_integrity_check', array($this, 'ms_run_integrity_check'));
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

    public function ms_run_integrity_check() {
        if (!$this->ms_get_option('enable_file_integrity', 1)) {
            return;
        }

        $this->ms_check_wordpress_core_integrity();
        $this->ms_check_plugins_integrity();
        $this->ms_check_themes_integrity();
    }

    public function ms_check_wordpress_core_integrity() {
        // Get WordPress version
        global $wp_version;

        // Get core files checksums from WordPress.org API
        $response = wp_remote_get("https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}");

        if (is_wp_error($response)) {
            $this->ms_log_security_event('integrity_check_failed',
                'Failed to fetch WordPress core checksums from API',
                'medium'
            );
            return;
        }

        $body = wp_remote_retrieve_body($response);
        $checksums = json_decode($body, true);

        if (!isset($checksums['checksums'])) {
            $this->ms_log_security_event('integrity_check_failed',
                'Invalid checksums data received from WordPress.org',
                'medium'
            );
            return;
        }

        $core_files = $checksums['checksums'];
        $modified_files = array();
        $missing_files = array();

        foreach ($core_files as $file => $expected_hash) {
            $file_path = ABSPATH . $file;

            if (!file_exists($file_path)) {
                $missing_files[] = $file;
                continue;
            }

            $actual_hash = md5_file($file_path);
            if ($actual_hash !== $expected_hash) {
                $modified_files[] = $file;
            }
        }

        // Log results
        if (!empty($modified_files)) {
            $this->ms_log_security_event('core_files_modified',
                'WordPress core files modified: ' . implode(', ', $modified_files),
                'critical'
            );
        }

        if (!empty($missing_files)) {
            $this->ms_log_security_event('core_files_missing',
                'WordPress core files missing: ' . implode(', ', $missing_files),
                'high'
            );
        }

        if (empty($modified_files) && empty($missing_files)) {
            $this->ms_log_security_event('integrity_check_passed',
                'WordPress core integrity check passed - all files intact',
                'low'
            );
        }

        // Store results for admin display
        update_option('ms_integrity_check_results', array(
            'last_check' => current_time('mysql'),
            'wp_version' => $wp_version,
            'modified_files' => $modified_files,
            'missing_files' => $missing_files,
            'status' => empty($modified_files) && empty($missing_files) ? 'clean' : 'infected'
        ));
    }

    public function ms_check_plugins_integrity() {
        $active_plugins = get_option('active_plugins', array());
        $plugin_issues = array();

        foreach ($active_plugins as $plugin_file) {
            $plugin_path = WP_PLUGIN_DIR . '/' . dirname($plugin_file);
            $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file);

            // Check if plugin is from WordPress.org repository
            $response = wp_remote_get("https://api.wordpress.org/plugins/info/1.0/" . dirname($plugin_file) . ".json");

            if (!is_wp_error($response)) {
                $body = wp_remote_retrieve_body($response);
                $plugin_info = json_decode($body, true);

                if (isset($plugin_info['version']) && $plugin_info['version'] !== $plugin_data['Version']) {
                    $plugin_issues[] = array(
                        'plugin' => $plugin_data['Name'],
                        'issue' => 'outdated',
                        'current' => $plugin_data['Version'],
                        'latest' => $plugin_info['version']
                    );
                }
            }

            // Check for suspicious files in plugin directory
            $suspicious_files = $this->ms_scan_directory_for_malware($plugin_path);
            if (!empty($suspicious_files)) {
                $plugin_issues[] = array(
                    'plugin' => $plugin_data['Name'],
                    'issue' => 'suspicious_files',
                    'files' => $suspicious_files
                );
            }
        }

        if (!empty($plugin_issues)) {
            $this->ms_log_security_event('plugin_integrity_issues',
                'Plugin integrity issues detected: ' . count($plugin_issues) . ' plugins affected',
                'medium'
            );
        }

        update_option('ms_plugin_integrity_results', array(
            'last_check' => current_time('mysql'),
            'issues' => $plugin_issues
        ));
    }

    public function ms_check_themes_integrity() {
        $themes = wp_get_themes();
        $theme_issues = array();

        foreach ($themes as $theme_slug => $theme) {
            $theme_path = $theme->get_stylesheet_directory();

            // Check for suspicious files in theme directory
            $suspicious_files = $this->ms_scan_directory_for_malware($theme_path);
            if (!empty($suspicious_files)) {
                $theme_issues[] = array(
                    'theme' => $theme->get('Name'),
                    'issue' => 'suspicious_files',
                    'files' => $suspicious_files
                );
            }
        }

        if (!empty($theme_issues)) {
            $this->ms_log_security_event('theme_integrity_issues',
                'Theme integrity issues detected: ' . count($theme_issues) . ' themes affected',
                'medium'
            );
        }

        update_option('ms_theme_integrity_results', array(
            'last_check' => current_time('mysql'),
            'issues' => $theme_issues
        ));
    }

    private function ms_scan_directory_for_malware($directory) {
        $suspicious_files = array();

        if (!is_dir($directory)) {
            return $suspicious_files;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $file_path = $file->getPathname();
            $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));

            // Only scan PHP files
            if ($extension !== 'php') {
                continue;
            }

            // Skip large files
            if (filesize($file_path) > 5 * 1024 * 1024) { // 5MB
                continue;
            }

            $content = file_get_contents($file_path);
            if ($this->ms_contains_malware_signatures($content)) {
                $suspicious_files[] = str_replace($directory, '', $file_path);
            }
        }

        return $suspicious_files;
    }

    private function ms_contains_malware_signatures($content) {
        $malware_signatures = array(
            '/eval\s*\(\s*base64_decode/i',
            '/eval\s*\(\s*gzinflate/i',
            '/eval\s*\(\s*str_rot13/i',
            '/system\s*\(\s*base64_decode/i',
            '/exec\s*\(\s*base64_decode/i',
            '/shell_exec\s*\(\s*base64_decode/i',
            '/passthru\s*\(\s*base64_decode/i',
            '/file_get_contents\s*\(\s*["\']https?:\/\/[^"\']*["\'].*eval/i',
            '/\$_POST\s*\[\s*["\'][^"\']*["\']\s*\]\s*\(\s*\$_POST/i',
            '/\$_GET\s*\[\s*["\'][^"\']*["\']\s*\]\s*\(\s*\$_GET/i',
            '/preg_replace\s*\(\s*["\'].*\/e["\'].*\$.*\)/i',
            '/assert\s*\(\s*\$_(GET|POST|REQUEST)/i',
            '/create_function\s*\(\s*["\'][^"\']*["\'].*eval/i'
        );

        foreach ($malware_signatures as $signature) {
            if (preg_match($signature, $content)) {
                return true;
            }
        }

        return false;
    }

    // Existing methods remain the same...
    private function ms_scan_core_files() {
        $upload_dir = wp_upload_dir();

        if (!is_dir($upload_dir['basedir'])) {
            return;
        }

        // Whitelist folders yang aman
        $safe_folders = $this->ms_get_safe_folders();

        // Suspicious extensions yang perlu dicek
        $suspicious_extensions = array('php', 'php3', 'php4', 'php5', 'phtml', 'js', 'html', 'htm');

        // Get scan settings
        $max_file_size = $this->ms_get_option('max_scan_file_size', 10) * 1024 * 1024; // Convert to bytes
        $scan_sensitivity = $this->ms_get_option('scan_sensitivity', 'medium');

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($upload_dir['basedir'], RecursiveDirectoryIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }

                $file_path = $file->getPathname();
                $relative_path = str_replace($upload_dir['basedir'], '', $file_path);

                // Skip jika file dalam folder yang di-whitelist
                if ($this->ms_is_in_safe_folder($relative_path, $safe_folders)) {
                    continue;
                }

                // Skip file yang terlalu besar
                if (filesize($file_path) > $max_file_size) {
                    continue;
                }

                // Skip jika file adalah legitimate plugin file
                if ($this->ms_is_legitimate_plugin_file($file_path)) {
                    continue;
                }

                $extension = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));

                // Hanya scan file dengan ekstensi yang suspicious
                if (in_array($extension, $suspicious_extensions)) {
                    // Lakukan pemeriksaan lebih mendalam
                    if ($this->ms_is_suspicious_file($file_path, $extension, $scan_sensitivity)) {
                        $this->ms_log_security_event('suspicious_file',
                            'Suspicious file detected: ' . $relative_path,
                            'medium'
                        );
                    }
                }
            }
        } catch (Exception $e) {
            $this->ms_log_security_event('scan_error',
                'Error during file scan: ' . $e->getMessage(),
                'low'
            );
        }
    }

    private function ms_get_safe_folders() {
        $default_safe_folders = array(
            // Plugin-specific folders
            '/forminator/',
            '/contact-form-7/',
            '/wpforms/',
            '/ninja-forms/',
            '/gravity-forms/',
            '/elementor/',
            '/beaver-builder/',
            '/divi/',
            '/wp-rocket/',
            '/litespeed-cache/',
            '/w3-total-cache/',
            '/wp-super-cache/',
            '/yoast-seo/',
            '/rankmath/',
            '/wordfence/',
            '/ithemes-security/',
            '/sucuri/',

            // Theme folders
            '/themes/',
            '/theme-backups/',

            // Backup folders
            '/backups/',
            '/backup/',
            '/updraftplus/',
            '/backwpup/',

            // Cache folders
            '/cache/',
            '/tmp/',
            '/temp/',

            // Media folders
            '/galleries/',
            '/slider/',
            '/revolution/',

            // E-commerce
            '/woocommerce_uploads/',
            '/edd/',

            // Common legitimate folders
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-content/mu-plugins/',
        );

        // Allow users to add custom safe folders
        $custom_safe_folders_string = $this->ms_get_option('custom_safe_folders', '');
        $custom_safe_folders = array();

        if (!empty($custom_safe_folders_string)) {
            $custom_safe_folders = array_filter(array_map('trim', explode("\n", $custom_safe_folders_string)));
        }

        return array_merge($default_safe_folders, $custom_safe_folders);
    }

    private function ms_is_in_safe_folder($file_path, $safe_folders) {
        foreach ($safe_folders as $safe_folder) {
            if (strpos($file_path, $safe_folder) !== false) {
                return true;
            }
        }
        return false;
    }

    private function ms_is_legitimate_plugin_file($file_path) {
        // Check apakah file berada dalam folder plugin yang terinstall
        $plugin_folders = array();

        // Get active plugins
        $active_plugins = get_option('active_plugins', array());
        foreach ($active_plugins as $plugin) {
            $plugin_folder = dirname($plugin);
            $plugin_folders[] = WP_CONTENT_DIR . '/plugins/' . $plugin_folder . '/';
        }

        // Get active theme
        $theme_folder = get_template_directory();
        $plugin_folders[] = $theme_folder . '/';

        // Check apakah file dalam folder plugin/theme yang legitimate
        foreach ($plugin_folders as $plugin_folder) {
            if (strpos($file_path, $plugin_folder) !== false) {
                return true;
            }
        }

        return false;
    }

    private function ms_is_suspicious_file($file_path, $extension, $sensitivity = 'medium') {
        // Check file content untuk PHP code yang mencurigakan
        if (in_array($extension, array('php', 'php3', 'php4', 'php5', 'phtml'))) {
            return $this->ms_scan_php_content($file_path, $sensitivity);
        }

        // Check JavaScript untuk suspicious patterns
        if ($extension === 'js') {
            return $this->ms_scan_js_content($file_path, $sensitivity);
        }

        // Check HTML untuk malicious scripts
        if (in_array($extension, array('html', 'htm'))) {
            return $this->ms_scan_html_content($file_path, $sensitivity);
        }

        return false;
    }

    private function ms_scan_php_content($file_path, $sensitivity) {
        $content = file_get_contents($file_path);

        if (empty($content)) {
            return false;
        }

        // Use the same malware signatures from integrity check
        return $this->ms_contains_malware_signatures($content);
    }

    private function ms_scan_js_content($file_path, $sensitivity) {
        $content = file_get_contents($file_path);

        if (empty($content)) {
            return false;
        }

        $suspicious_patterns = array(
            '/eval\s*\(/i',
            '/document\.write\s*\(/i',
            '/innerHTML\s*=.*<script/i',
        );

        if ($sensitivity === 'medium' || $sensitivity === 'high') {
            $additional_patterns = array(
                '/fromCharCode/i',
                '/unescape\s*\(/i',
                '/String\.fromCharCode/i'
            );
            $suspicious_patterns = array_merge($suspicious_patterns, $additional_patterns);
        }

        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    private function ms_scan_html_content($file_path, $sensitivity) {
        $content = file_get_contents($file_path);

        if (empty($content)) {
            return false;
        }

        $suspicious_patterns = array(
            '/<script[^>]*>.*eval\s*\(/is',
            '/<iframe[^>]*src\s*=\s*["\']https?:\/\/[^"\']*["\'][^>]*>/i',
        );

        if ($sensitivity === 'high') {
            $additional_patterns = array(
                '/<script[^>]*>.*document\.write/is',
                '/javascript\s*:\s*eval\s*\(/i',
            );
            $suspicious_patterns = array_merge($suspicious_patterns, $additional_patterns);
        }

        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
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
        $rate_limiter = MS_Rate_Limiter::get_instance();
        $ip_address = $this->ms_get_user_ip();

        // Check if we should log this event
        if (!$rate_limiter->should_log_event($event_type, $ip_address)) {
            return;
        }

        // Get country if not provided and geolocation is enabled
        if (!$country && $this->ms_get_option('enable_geolocation', 1)) {
            $country = $this->ms_get_country_from_ip();
        }

        // Get current path if not provided
        if (!$path) {
            $path = $_SERVER['REQUEST_URI'] ?? '';
        }

        // Use async logger
        $logger = MS_Logger::get_instance();
        $logger->queue_log($event_type, $description, $severity, $user_id, $country, $path);
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
