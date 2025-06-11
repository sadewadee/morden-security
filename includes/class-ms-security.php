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
        add_action('init', array($this, 'ms_early_security_checks'), 1);

        if ($this->core->ms_get_option('disable_file_editor', 1)) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }

        if ($this->core->ms_get_option('force_ssl', 1)) {
            add_action('init', array($this, 'ms_force_ssl'));
        }

        if ($this->core->ms_get_option('disable_xmlrpc', 1)) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', array($this, 'ms_remove_xmlrpc_headers'));
            add_action('xmlrpc_call', array($this, 'ms_log_xmlrpc_attempt'));
        }

        if ($this->core->ms_get_option('block_php_uploads', 1)) {
            add_action('init', array($this, 'ms_block_php_uploads'));
        }

        if ($this->core->ms_get_option('disable_pingbacks', 1)) {
            add_action('init', array($this, 'ms_disable_pingbacks'));
        }

        if ($this->core->ms_get_option('enable_bot_protection', 1)) {
            add_action('init', array($this, 'ms_bot_protection'));
        }

        if ($this->core->ms_get_option('block_author_scans', 1)) {
            add_action('init', array($this, 'ms_block_author_scans'));
        }

        if ($this->core->ms_get_option('hide_login_url', 0)) {
            add_action('init', array($this, 'ms_hide_login_url'));
            add_filter('site_url', array($this, 'ms_filter_site_url'), 10, 4);
            add_filter('wp_redirect', array($this, 'ms_filter_wp_redirect'), 10, 2);
            add_filter('login_url', array($this, 'ms_filter_login_url'), 10, 3);
        }

        if ($this->core->ms_get_option('limit_login_attempts', 1)) {
            add_action('wp_login_failed', array($this, 'ms_handle_failed_login'));
            add_filter('authenticate', array($this, 'ms_check_login_attempts'), 30, 3);
            add_action('wp_login', array($this, 'ms_handle_successful_login'), 10, 2);
        }

        if ($this->core->ms_get_option('enable_security_headers', 1)) {
            add_action('send_headers', array($this, 'ms_add_security_headers'));
        }

        if ($this->core->ms_get_option('turnstile_enabled', 0)) {
            add_action('login_form', array($this, 'ms_add_turnstile_to_login'));
            add_action('register_form', array($this, 'ms_add_turnstile_to_register'));
            add_filter('authenticate', array($this, 'ms_verify_turnstile'), 20, 3);
        }

        if ($this->core->ms_get_option('scan_uploads', 1)) {
            add_filter('wp_handle_upload_prefilter', array($this, 'ms_scan_upload'));
        }
    }

    public function ms_bot_protection() {
        if ($this->core->ms_get_option('enable_6g_firewall', 1)) {
            return;
        }

        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $bad_bots = array(
            'sqlmap', 'nikto', 'nessus', 'openvas', 'w3af', 'skipfish',
            'grabber', 'wpscan', 'dirbuster', 'nmap', 'masscan', 'zmap',
            'shodan', 'censys'
        );

        foreach ($bad_bots as $bot) {
            if (stripos($user_agent, $bot) !== false) {
                $this->core->ms_log_security_event('bot_blocked',
                    'Malicious bot blocked: ' . $bot,
                    'medium'
                );

                wp_die(__('Access denied for security reasons.', 'morden-security'),
                    __('Bot Blocked', 'morden-security'),
                    array('response' => 403));
            }
        }

        if (empty($user_agent)) {
            $this->core->ms_log_security_event('empty_user_agent',
                'Request with empty user agent blocked',
                'low'
            );

            wp_die(__('Access denied for security reasons.', 'morden-security'),
                __('Invalid Request', 'morden-security'),
                array('response' => 403));
        }
    }

    public function ms_hide_login_url() {
        $custom_login = $this->core->ms_get_option('custom_login_url', 'secure-login');

        $request = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $request = trim($request, '/');

        if (in_array($request, array('wp-admin', 'wp-login.php'))) {
            if (defined('DOING_AJAX') && DOING_AJAX) {
                return;
            }

            if (is_user_logged_in()) {
                return;
            }

            $this->core->ms_log_security_event('login_url_blocked',
                'Blocked access to default login URL: ' . $request,
                'medium'
            );

            status_header(404);
            include(get_404_template());
            exit;
        }

        if ($request === $custom_login) {
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    public function ms_filter_site_url($url, $path, $scheme, $blog_id) {
        if ($path === 'wp-login.php' || $path === '/wp-login.php') {
            $custom_login = $this->core->ms_get_option('custom_login_url', 'secure-login');
            return home_url($custom_login, $scheme);
        }
        return $url;
    }

    public function ms_filter_wp_redirect($location, $status) {
        if (strpos($location, 'wp-login.php') !== false) {
            $custom_login = $this->core->ms_get_option('custom_login_url', 'secure-login');
            $location = str_replace('wp-login.php', $custom_login, $location);
        }
        return $location;
    }

    public function ms_filter_login_url($login_url, $redirect, $force_reauth) {
        $custom_login = $this->core->ms_get_option('custom_login_url', 'secure-login');
        $login_url = str_replace('wp-login.php', $custom_login, $login_url);
        return $login_url;
    }


    public function ms_block_php_uploads() {
        // Create .htaccess in uploads directory
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';

        if (!file_exists($htaccess_file)) {
            $htaccess_content = "# Morden Security - Block PHP execution\n";
            $htaccess_content .= "<Files *.php>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.php3>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.php4>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.php5>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.phtml>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";

            file_put_contents($htaccess_file, $htaccess_content);
        }

        // Also block via upload filter
        add_filter('wp_handle_upload_prefilter', array($this, 'ms_block_php_upload_filter'));
    }

    public function ms_block_php_upload_filter($file) {
        $php_extensions = array('php', 'php3', 'php4', 'php5', 'phtml', 'pht');
        $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

        if (in_array($file_extension, $php_extensions)) {
            $file['error'] = __('PHP files are not allowed for security reasons.', 'morden-security');
            $this->core->ms_log_security_event('php_upload_blocked',
                'Attempted PHP file upload blocked: ' . $file['name'],
                'high'
            );
        }

        return $file;
    }

    public function ms_disable_pingbacks() {
        // Disable pingback functionality
        add_filter('xmlrpc_methods', array($this, 'ms_remove_pingback_methods'));
        add_filter('wp_headers', array($this, 'ms_remove_pingback_header'));
        add_filter('bloginfo_url', array($this, 'ms_remove_pingback_url'), 10, 2);

        // Remove pingback from HTML head
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');

        // Disable self-pingbacks
        add_action('pre_ping', array($this, 'ms_disable_self_pingbacks'));

        // Close comments on old posts
        add_filter('comments_open', array($this, 'ms_close_comments_for_old_posts'), 10, 2);
        add_filter('pings_open', array($this, 'ms_close_pings_for_old_posts'), 10, 2);
    }

    public function ms_remove_pingback_methods($methods) {
        unset($methods['pingback.ping']);
        unset($methods['pingback.extensions.getPingbacks']);
        return $methods;
    }

    public function ms_remove_pingback_header($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    public function ms_remove_pingback_url($output, $show) {
        if ($show === 'pingback_url') {
            return '';
        }
        return $output;
    }

    public function ms_disable_self_pingbacks(&$links) {
        $home = get_option('home');
        foreach ($links as $l => $link) {
            if (0 === strpos($link, $home)) {
                unset($links[$l]);
            }
        }
    }

    public function ms_close_comments_for_old_posts($open, $post_id) {
        if (!$open) {
            return $open;
        }

        $post = get_post($post_id);
        if (!$post) {
            return $open;
        }

        // Close comments for posts older than 30 days
        if (time() - strtotime($post->post_date_gmt) > (30 * 24 * 60 * 60)) {
            return false;
        }

        return $open;
    }

    public function ms_close_pings_for_old_posts($open, $post_id) {
        return false; // Always disable pings
    }

    private function ms_is_legitimate_bot($user_agent) {
        $legitimate_bots = array(
            'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
            'yandexbot', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
            'whatsapp', 'telegrambot', 'applebot', 'discordbot'
        );

        foreach ($legitimate_bots as $bot) {
            if (stripos($user_agent, $bot) !== false) {
                return true;
            }
        }

        return false;
    }

    public function ms_block_author_scans() {
        // Block author enumeration attempts
        if (isset($_GET['author']) && is_numeric($_GET['author'])) {
            $this->core->ms_log_security_event('author_scan_blocked',
                'Author enumeration attempt blocked for author ID: ' . $_GET['author'],
                'medium'
            );

            wp_die(__('Author enumeration is not allowed.', 'morden-security'),
                   __('Access Denied', 'morden-security'),
                   array('response' => 403));
        }

        // Block REST API user enumeration
        add_filter('rest_endpoints', array($this, 'ms_disable_rest_user_endpoints'));

        // Block author archives for non-logged in users
        add_action('template_redirect', array($this, 'ms_block_author_archives'));
    }

    public function ms_disable_rest_user_endpoints($endpoints) {
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
        return $endpoints;
    }

    public function ms_block_author_archives() {
        if (is_author() && !is_user_logged_in()) {
            $this->core->ms_log_security_event('author_archive_blocked',
                'Author archive access blocked for non-logged user',
                'low'
            );

            wp_redirect(home_url(), 301);
            exit;
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
        $allowed_extensions = array('jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip', 'rar');
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