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
        $upload_dir = wp_upload_dir();

        if (!is_dir($upload_dir['basedir'])) {
            return;
        }

        // Whitelist folders yang aman
        $safe_folders = $this->ms_get_safe_folders();

        // Whitelist file extensions yang legitimate
        $safe_extensions = $this->ms_get_safe_extensions();

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

    private function ms_get_safe_extensions() {
        return array(
            // Images
            'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico',

            // Documents
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf',

            // Archives
            'zip', 'rar', '7z', 'tar', 'gz',

            // Audio/Video
            'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'wav', 'ogg',

            // Fonts
            'ttf', 'otf', 'woff', 'woff2', 'eot',

            // Data files
            'json', 'xml', 'csv', 'log', 'css'
        );
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

        // Basic malicious PHP patterns
        $basic_patterns = array(
            '/eval\s*\(/i',
            '/base64_decode\s*\(/i',
            '/shell_exec\s*\(/i',
            '/system\s*\(/i',
            '/exec\s*\(/i',
            '/passthru\s*\(/i',
        );

        // Advanced malicious patterns
        $advanced_patterns = array(
            '/file_get_contents\s*\(\s*["\']https?:\/\//i',
            '/curl_exec\s*\(/i',
            '/\$_GET\s*\[\s*["\'][^"\']*["\'].*eval/i',
            '/\$_POST\s*\[\s*["\'][^"\']*["\'].*eval/i',
            '/preg_replace.*\/e["\'].*\$/i',
            '/assert\s*\(/i',
            '/create_function\s*\(/i',
        );

        $patterns_to_check = $basic_patterns;

        if ($sensitivity === 'medium' || $sensitivity === 'high') {
            $patterns_to_check = array_merge($patterns_to_check, $advanced_patterns);
        }

        foreach ($patterns_to_check as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        // Check untuk obfuscated code (hanya pada sensitivity high)
        if ($sensitivity === 'high' && $this->ms_is_obfuscated_php($content)) {
            return true;
        }

        return false;
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

    private function ms_is_obfuscated_php($content) {
        // Check untuk heavily obfuscated code
        $obfuscation_indicators = array(
            // Too many base64 strings
            substr_count($content, 'base64') > 5,

            // Too many eval calls
            substr_count($content, 'eval') > 3,

            // Excessive use of chr() function
            substr_count($content, 'chr(') > 10,

            // Very long lines (often sign of obfuscation)
            max(array_map('strlen', explode("\n", $content))) > 1000,

            // High ratio of non-alphanumeric characters
            (strlen($content) - strlen(preg_replace('/[^a-zA-Z0-9]/', '', $content))) / strlen($content) > 0.7
        );

        // Return true if 2 or more indicators are present
        return count(array_filter($obfuscation_indicators)) >= 2;
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
