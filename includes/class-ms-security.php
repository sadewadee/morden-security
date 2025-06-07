<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Security {

    private static $instance = null;
    private $core;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->core = MS_Core::get_instance();
        $this->ms_init_security_features();
    }

    private function ms_init_security_features() {
        // Early security checks
        add_action('init', array($this, 'ms_early_security_checks'), 1);

        // Disable file editor
        if ($this->core->ms_get_option('disable_file_editor', 1)) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }

        // Force SSL
        if ($this->core->ms_get_option('force_ssl', 1)) {
            add_action('init', array($this, 'ms_force_ssl'));
        }

        // Disable XML-RPC
        if ($this->core->ms_get_option('disable_xmlrpc', 1)) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', array($this, 'ms_remove_xmlrpc_headers'));
            add_action('xmlrpc_call', array($this, 'ms_log_xmlrpc_attempt'));
        }

        // Login protection
        if ($this->core->ms_get_option('limit_login_attempts', 1)) {
            add_action('wp_login_failed', array($this, 'ms_handle_failed_login'));
            add_filter('authenticate', array($this, 'ms_check_login_attempts'), 30, 3);
            add_action('wp_login', array($this, 'ms_handle_successful_login'), 10, 2);
        }

        // Security headers
        if ($this->core->ms_get_option('enable_security_headers', 1)) {
            add_action('send_headers', array($this, 'ms_add_security_headers'));
        }

        // Cloudflare Turnstile
        if ($this->core->ms_get_option('turnstile_enabled', 0)) {
            add_action('login_form', array($this, 'ms_add_turnstile_to_login'));
            add_action('register_form', array($this, 'ms_add_turnstile_to_register'));
            add_filter('authenticate', array($this, 'ms_verify_turnstile'), 20, 3);
        }

        // Firewall
        if ($this->core->ms_get_option('enable_firewall', 1)) {
            add_action('init', array($this, 'ms_firewall_check'));
        }

        // Upload scanning
        if ($this->core->ms_get_option('scan_uploads', 1)) {
            add_filter('wp_handle_upload_prefilter', array($this, 'ms_scan_upload'));
        }

        // Block suspicious requests
        if ($this->core->ms_get_option('block_suspicious_requests', 1)) {
            add_action('init', array($this, 'ms_block_suspicious_requests'));
        }
    }

    public function ms_early_security_checks() {
        // Check if IP is blocked
        if ($this->core->ms_is_ip_blocked()) {
            wp_die(__('Your IP address has been blocked due to security reasons.', 'morden-security'),
                   __('Access Denied', 'morden-security'),
                   array('response' => 403));
        }
    }

    public function ms_force_ssl() {
        if (!is_ssl() && !is_admin()) {
            $redirect_url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            wp_redirect($redirect_url, 301);
            exit();
        }
    }

    public function ms_remove_xmlrpc_headers($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    public function ms_log_xmlrpc_attempt() {
        $this->core->ms_log_security_event('xmlrpc_attempt',
            'XML-RPC access attempt blocked',
            'medium'
        );
    }

    public function ms_handle_failed_login($username) {
        global $wpdb;

        $ip = $this->core->ms_get_user_ip();
        $table_name = $wpdb->prefix . 'ms_login_attempts';
        $max_attempts = $this->core->ms_get_option('max_login_attempts', 5);
        $lockout_duration = $this->core->ms_get_option('lockout_duration', 1800);

        // Get current attempts
        $current_attempts = $wpdb->get_var($wpdb->prepare(
            "SELECT attempts FROM $table_name WHERE ip_address = %s",
            $ip
        ));

        if ($current_attempts) {
            $new_attempts = $current_attempts + 1;
            $locked_until = ($new_attempts >= $max_attempts) ? date('Y-m-d H:i:s', time() + $lockout_duration) : null;

            $wpdb->update(
                $table_name,
                array(
                    'attempts' => $new_attempts,
                    'locked_until' => $locked_until,
                    'last_attempt' => current_time('mysql'),
                    'username' => sanitize_user($username),
                    'user_agent' => sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? '')
                ),
                array('ip_address' => $ip)
            );

            if ($new_attempts >= $max_attempts) {
                $this->core->ms_log_security_event('login_lockout',
                    "IP locked after $new_attempts failed attempts for user: $username",
                    'high'
                );
            }
        } else {
            $wpdb->insert(
                $table_name,
                array(
                    'ip_address' => $ip,
                    'username' => sanitize_user($username),
                    'attempts' => 1,
                    'last_attempt' => current_time('mysql'),
                    'user_agent' => sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? '')
                )
            );
        }

        $this->core->ms_log_security_event('login_failed',
            "Failed login attempt for user: $username",
            'medium'
        );
    }

    public function ms_check_login_attempts($user, $username, $password) {
        if (empty($username) || empty($password)) {
            return $user;
        }

        global $wpdb;

        $ip = $this->core->ms_get_user_ip();
        $table_name = $wpdb->prefix . 'ms_login_attempts';

        $attempt_data = $wpdb->get_row($wpdb->prepare(
            "SELECT attempts, locked_until FROM $table_name WHERE ip_address = %s",
            $ip
        ));

        if ($attempt_data && $attempt_data->locked_until && strtotime($attempt_data->locked_until) > time()) {
            $remaining_time = strtotime($attempt_data->locked_until) - time();
            return new WP_Error('ms_locked_out',
                sprintf(__('Too many failed login attempts. Please try again in %d minutes.', 'morden-security'),
                ceil($remaining_time / 60))
            );
        }

        return $user;
    }

    public function ms_handle_successful_login($user_login, $user) {
        global $wpdb;

        $ip = $this->core->ms_get_user_ip();
        $table_name = $wpdb->prefix . 'ms_login_attempts';

        // Reset login attempts on successful login
        $wpdb->delete($table_name, array('ip_address' => $ip));

        $this->core->ms_log_security_event('login_success',
            "Successful login for user: $user_login",
            'low',
            $user->ID
        );
    }

    public function ms_add_security_headers() {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
        header('Content-Security-Policy: frame-ancestors \'self\'');

        if (is_ssl()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
    }

    public function ms_add_turnstile_to_login() {
        $site_key = $this->core->ms_get_option('turnstile_site_key', '');
        if (empty($site_key)) {
            return;
        }

        echo '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
        echo '<div class="cf-turnstile" data-sitekey="' . esc_attr($site_key) . '" style="margin: 10px 0;"></div>';
    }

    public function ms_add_turnstile_to_register() {
        $this->ms_add_turnstile_to_login();
    }

    public function ms_verify_turnstile($user, $username, $password) {
        if (empty($username) || empty($password)) {
            return $user;
        }

        $secret_key = $this->core->ms_get_option('turnstile_secret_key', '');
        if (empty($secret_key)) {
            return $user;
        }

        $token = $_POST['cf-turnstile-response'] ?? '';
        if (empty($token)) {
            return new WP_Error('ms_turnstile_missing', __('Please complete the security check.', 'morden-security'));
        }

        $response = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', array(
            'body' => array(
                'secret' => $secret_key,
                'response' => $token,
                'remoteip' => $this->core->ms_get_user_ip()
            ),
            'timeout' => 10
        ));

        if (is_wp_error($response)) {
            return new WP_Error('ms_turnstile_error', __('Security verification failed. Please try again.', 'morden-security'));
        }

        $body = wp_remote_retrieve_body($response);
        $result = json_decode($body, true);

        if (!$result['success']) {
            $this->core->ms_log_security_event('turnstile_failed',
                'Turnstile verification failed for user: ' . $username,
                'medium'
            );
            return new WP_Error('ms_turnstile_failed', __('Security verification failed. Please try again.', 'morden-security'));
        }

        return $user;
    }

    public function ms_firewall_check() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Check for common attack patterns
        $malicious_patterns = array(
            '/\.\./i',                    // Directory traversal
            '/union.*select/i',           // SQL injection
            '/<script/i',                 // XSS
            '/javascript:/i',             // XSS
            '/eval\(/i',                  // Code injection
            '/base64_decode/i',           // Code injection
            '/GLOBALS/i',                 // Variable injection
            '/_REQUEST/i',                // Variable injection
        );

        $suspicious_user_agents = array(
            'sqlmap',
            'nikto',
            'nessus',
            'OpenVAS',
            'w3af'
        );

        // Check request URI and query string
        foreach ($malicious_patterns as $pattern) {
            if (preg_match($pattern, $request_uri . $query_string)) {
                $this->core->ms_block_ip($this->core->ms_get_user_ip(),
                    'Malicious request pattern detected',
                    3600
                );
                wp_die(__('Malicious request detected.', 'morden-security'),
                       __('Security Alert', 'morden-security'),
                       array('response' => 403));
            }
        }

        // Check user agent
        foreach ($suspicious_user_agents as $agent) {
            if (stripos($user_agent, $agent) !== false) {
                $this->core->ms_block_ip($this->core->ms_get_user_ip(),
                    'Suspicious user agent: ' . $agent,
                    7200
                );
                wp_die(__('Suspicious activity detected.', 'morden-security'),
                       __('Security Alert', 'morden-security'),
                       array('response' => 403));
            }
        }
    }

    public function ms_scan_upload($file) {
        $filename = $file['name'];
        $tmp_name = $file['tmp_name'];

        // Check file extension
        $allowed_extensions = array('jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt');
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        if (!in_array($file_extension, $allowed_extensions)) {
            $file['error'] = __('File type not allowed for security reasons.', 'morden-security');
            return $file;
        }

        // Check file content for PHP code
        if (is_readable($tmp_name)) {
            $content = file_get_contents($tmp_name);
            if (preg_match('/<\?php|<\?=|\<\%/i', $content)) {
                $file['error'] = __('File contains suspicious code and cannot be uploaded.', 'morden-security');
                $this->core->ms_log_security_event('malicious_upload',
                    'Attempted upload of file with PHP code: ' . $filename,
                    'high'
                );
                return $file;
            }
        }

        return $file;
    }

    public function ms_block_suspicious_requests() {
        // Block requests with suspicious POST data
        if ($_POST) {
            $post_data = serialize($_POST);
            $suspicious_patterns = array(
                '/union.*select/i',
                '/script/i',
                '/javascript:/i',
                '/vbscript:/i',
                '/onload=/i',
                '/onerror=/i'
            );

            foreach ($suspicious_patterns as $pattern) {
                if (preg_match($pattern, $post_data)) {
                    $this->core->ms_log_security_event('suspicious_post',
                        'Suspicious POST data detected',
                        'high'
                    );
                    wp_die(__('Suspicious data detected in request.', 'morden-security'),
                           __('Security Alert', 'morden-security'),
                           array('response' => 403));
                }
            }
        }
    }
}