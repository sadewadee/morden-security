<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Firewall {

    private static $instance = null;
    private $core;
    private $whitelisted_ips = array();
    private $server_ips = array();
    private $logged_in_ips = array();

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->core = MS_Core::get_instance();
        $this->init_whitelist();
        $this->init_firewall();
    }

    private function init_firewall() {
        $firewall_mode = $this->core->ms_get_option('firewall_mode', '6g');

        if ($firewall_mode === '6g' && $this->core->ms_get_option('enable_6g_firewall', 1)) {
            add_action('init', array($this, 'apply_6g_firewall'), 1);
        } elseif ($firewall_mode === 'basic' && $this->core->ms_get_option('enable_basic_firewall', 1)) {
            add_action('init', array($this, 'basic_firewall_check'), 3);
        }

        // Track user logins for whitelist
        add_action('wp_login', array($this, 'track_user_login'), 10, 2);
        add_action('wp_logout', array($this, 'track_user_logout'));

        // Periodic whitelist refresh
        add_action('init', array($this, 'refresh_whitelist'), 5);
    }

    private function init_whitelist() {
        $this->server_ips = $this->get_server_ips();
        $this->logged_in_ips = $this->get_logged_in_user_ips();

        $this->whitelisted_ips = array_merge(
            $this->server_ips,
            $this->logged_in_ips,
            $this->get_admin_ips(),
            $this->get_custom_whitelist_ips(),
            $this->get_hosting_provider_ips()
        );

        $this->whitelisted_ips = array_unique(array_filter($this->whitelisted_ips));
    }

    public function refresh_whitelist() {
        // Only refresh every 5 minutes to avoid performance issues
        $last_refresh = get_transient('ms_whitelist_last_refresh');
        if ($last_refresh && (time() - $last_refresh) < 300) {
            return;
        }

        $this->init_whitelist();
        set_transient('ms_whitelist_last_refresh', time(), 300);
    }

    private function get_server_ips() {
        $server_ips = array();

        // Get server IP address
        if (isset($_SERVER['SERVER_ADDR']) && !empty($_SERVER['SERVER_ADDR'])) {
            $server_ips[] = $_SERVER['SERVER_ADDR'];
        }

        // Get server hostname IP
        $server_name = $_SERVER['SERVER_NAME'] ?? $_SERVER['HTTP_HOST'] ?? '';
        if (!empty($server_name)) {
            $server_ip = gethostbyname($server_name);
            if ($server_ip && $server_ip !== $server_name && filter_var($server_ip, FILTER_VALIDATE_IP)) {
                $server_ips[] = $server_ip;
            }
        }

        // Common localhost and private IPs
        $localhost_ips = array(
            '127.0.0.1', '::1', 'localhost',
            '192.168.1.1', '10.0.0.1', '172.16.0.1'
        );
        $server_ips = array_merge($server_ips, $localhost_ips);

        // Get load balancer IPs if behind proxy
        $proxy_headers = array(
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED'
        );

        foreach ($proxy_headers as $header) {
            if (isset($_SERVER[$header]) && !empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)) {
                        $server_ips[] = $ip;
                    }
                }
            }
        }

        return array_unique(array_filter($server_ips));
    }

    private function get_hosting_provider_ips() {
        $hosting_ips = array();
        $current_ip = $this->core->ms_get_user_ip();

        // CloudFlare IP ranges
        $cloudflare_ranges = array(
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        );

        // Check if current IP is from CloudFlare
        foreach ($cloudflare_ranges as $range) {
            if ($this->ip_in_range($current_ip, $range)) {
                $hosting_ips[] = $current_ip;
                break;
            }
        }

        // Common hosting provider ranges
        $hosting_ranges = array(
            '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'
        );

        foreach ($hosting_ranges as $range) {
            if ($this->ip_in_range($current_ip, $range)) {
                $hosting_ips[] = $current_ip;
                break;
            }
        }

        return array_unique($hosting_ips);
    }

    private function get_logged_in_user_ips() {
        $logged_in_ips = array();

        // Get cached logged in users
        $logged_in_users = get_transient('ms_logged_in_users');
        if (!$logged_in_users) {
            $logged_in_users = array();
        }

        // Add current user IP if logged in
        if (is_user_logged_in()) {
            $current_ip = $this->core->ms_get_user_ip();
            $user_id = get_current_user_id();

            $logged_in_users[$user_id] = array(
                'ip' => $current_ip,
                'timestamp' => time(),
                'user_login' => wp_get_current_user()->user_login,
                'user_role' => wp_get_current_user()->roles[0] ?? 'subscriber'
            );

            $logged_in_ips[] = $current_ip;
        }

        // Clean old entries and collect active IPs
        $current_time = time();
        $session_timeout = $this->core->ms_get_option('whitelist_session_timeout', 3600); // 1 hour default

        foreach ($logged_in_users as $user_id => $data) {
            if (($current_time - $data['timestamp']) < $session_timeout) {
                $logged_in_ips[] = $data['ip'];
            } else {
                unset($logged_in_users[$user_id]);
            }
        }

        // Update transient
        set_transient('ms_logged_in_users', $logged_in_users, $session_timeout);

        return array_unique($logged_in_ips);
    }

    private function get_admin_ips() {
        $admin_ips = array();

        // Get admin IPs from settings
        $admin_ip_list = $this->core->ms_get_option('admin_whitelist_ips', '');
        if (!empty($admin_ip_list)) {
            $admin_ips = array_map('trim', explode("\n", $admin_ip_list));
            $admin_ips = array_filter($admin_ips, function($ip) {
                return filter_var(trim($ip), FILTER_VALIDATE_IP);
            });
        }

        // Auto-detect and save admin IP on first admin login
        if (is_user_logged_in() && current_user_can('manage_options')) {
            $current_ip = $this->core->ms_get_user_ip();
            if (!in_array($current_ip, $admin_ips) && filter_var($current_ip, FILTER_VALIDATE_IP)) {
                $admin_ips[] = $current_ip;

                // Auto-save admin IP
                $updated_list = implode("\n", array_unique($admin_ips));
                $options = get_option('ms_settings', array());
                $options['admin_whitelist_ips'] = $updated_list;
                update_option('ms_settings', $options);

                $this->core->ms_log_security_event('admin_ip_auto_added',
                    "Admin IP automatically added to whitelist: {$current_ip}",
                    'low'
                );
            }
        }

        return array_unique($admin_ips);
    }

    private function get_custom_whitelist_ips() {
        $custom_ips = array();

        // Get custom whitelist from settings
        $custom_ip_list = $this->core->ms_get_option('custom_whitelist_ips', '');
        if (!empty($custom_ip_list)) {
            $custom_ips = array_map('trim', explode("\n", $custom_ip_list));
            $custom_ips = array_filter($custom_ips, function($ip) {
                return filter_var(trim($ip), FILTER_VALIDATE_IP) || $this->is_valid_ip_range(trim($ip));
            });
        }

        return array_unique($custom_ips);
    }

    private function is_valid_ip_range($range) {
        // Check CIDR notation
        if (strpos($range, '/') !== false) {
            list($ip, $mask) = explode('/', $range);
            return filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($mask) && $mask >= 0 && $mask <= 32;
        }

        // Check wildcard notation
        if (strpos($range, '*') !== false) {
            $pattern = str_replace('*', '([0-9]{1,3})', preg_quote($range, '/'));
            return preg_match('/^' . $pattern . '$/', '192.168.1.1') !== false;
        }

        return false;
    }

    public function is_ip_whitelisted($ip) {
        // Refresh whitelist if needed
        $this->refresh_whitelist();

        // Check exact IP match
        if (in_array($ip, $this->whitelisted_ips)) {
            return true;
        }

        // Check IP ranges from settings
        $ip_ranges = $this->core->ms_get_option('whitelist_ip_ranges', '');
        if (!empty($ip_ranges)) {
            $ranges = array_map('trim', explode("\n", $ip_ranges));
            foreach ($ranges as $range) {
                if ($this->ip_in_range($ip, $range)) {
                    return true;
                }
            }
        }

        // Check custom whitelist IPs (including ranges)
        $custom_ips = $this->get_custom_whitelist_ips();
        foreach ($custom_ips as $custom_ip) {
            if ($this->ip_in_range($ip, $custom_ip)) {
                return true;
            }
        }

        return false;
    }

    private function ip_in_range($ip, $range) {
        if (strpos($range, '/') !== false) {
            // CIDR notation
            list($subnet, $mask) = explode('/', $range);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);

            if ($ip_long === false || $subnet_long === false) {
                return false;
            }

            $mask_long = -1 << (32 - (int)$mask);
            return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
        } else {
            // Exact match or wildcard
            if (strpos($range, '*') !== false) {
                $pattern = str_replace('*', '([0-9]{1,3})', preg_quote($range, '/'));
                return preg_match('/^' . $pattern . '$/', $ip) === 1;
            }
            return $ip === $range;
        }
    }

    private function should_apply_firewall_protection() {
        $current_ip = $this->core->ms_get_user_ip();

        // Skip if IP is whitelisted
        if ($this->is_ip_whitelisted($current_ip)) {
            return false;
        }

        // Skip for AJAX requests from logged in users
        if (defined('DOING_AJAX') && DOING_AJAX && is_user_logged_in()) {
            return false;
        }

        // Skip for cron jobs
        if (defined('DOING_CRON') && DOING_CRON) {
            return false;
        }

        // Skip for admin area if user is logged in with admin privileges
        if (is_admin() && is_user_logged_in() && current_user_can('manage_options')) {
            return false;
        }

        // Skip for REST API requests from authenticated users
        if (defined('REST_REQUEST') && REST_REQUEST && is_user_logged_in()) {
            return false;
        }

        // Skip for XML-RPC if user is authenticated
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST && is_user_logged_in()) {
            return false;
        }

        return true;
    }

    public function apply_6g_firewall() {
        if (!$this->should_apply_firewall_protection()) {
            return;
        }

        $this->check_6g_query_string();
        $this->check_6g_request_uri();
        $this->check_6g_request_method();
        $this->check_6g_http_headers();

        // Only check user agent if bot protection is disabled
        if (!$this->core->ms_get_option('enable_bot_protection', 1)) {
            $this->check_6g_user_agent();
        }
    }

    private function check_6g_query_string() {
        $query_string = $_SERVER['QUERY_STRING'] ?? '';

        if (empty($query_string)) {
            return;
        }

        $six_g_patterns = array(
            '/(eval\()/i',
            '/(127\.0\.0\.1)/i',
            '/([a-z0-9]{2000,})/i',
            '/(javascript:)(.*)(;)/i',
            '/(base64_encode)(.*)(\()/i',
            '/(GLOBALS|REQUEST)(=|\[)/i',
            '/(<|%3C)(.*)script(.*)(>|%3E)/i',
            '/(\\\\|\.\.\.|\.\./|~|`|<|>|\|)/i',
            '/(boot\.ini|etc\/passwd|self\/environ)/i',
            '/(thumbs?(_editor|open)?|tim(thumb)?)\.php/i',
            '/(\'|\")(.*)(drop|insert|md5|select|union)/i',
            '/(union|select|insert|update|delete|drop|create|alter)/i',
            '/(concat|load_file|outfile|dumpfile)/i',
            '/(benchmark|sleep|get_lock|release_lock)/i',
            '/(information_schema|mysql\.)/i'
        );

        foreach ($six_g_patterns as $pattern) {
            if (preg_match($pattern, $query_string)) {
                $this->block_6g_request('6g_query_string', $pattern, $query_string);
                return;
            }
        }
    }

    private function check_6g_request_uri() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';

        if (empty($request_uri)) {
            return;
        }

        $six_g_uri_patterns = array(
            '/([a-z0-9]{2000,})/i',
            '/(https?|ftp|php):\//i',
            '/(base64_encode)(.*)(\()/i',
            '/(=\\\\\'|=\\\\%27|\/\\\\\'\/?)\\./i',
            '/\/(\$(\&)?|\*|\"|\.|,|&|&?)\/?$/i',
            '/(\{0\}|\(\/\(|\.\.\.|\+\+\+|\\\\\"\\\\\")/i',
            '/(~|`|<|>|:|;|,|%|\\\\|\{|\}|\[|\]|\|)/i',
            '/\/(=|\$&|_mm|cgi-|muieblack)/i',
            '/(&pws=0|_vti_|\(null\)|\{\$itemURL\}|echo(.*)kae|etc\/passwd|eval\(|self\/environ)/i',
            '/\.(aspx?|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rar|rdf)$/i',
            '/\/(^$|(wp-)?config|mobiquo|phpinfo|shell|sqlpatch|thumb|thumb_editor|thumbopen|timthumb|webshell)\.php/i',
            '/(union|select|insert|update|delete|drop|create|alter)/i',
            '/(concat|load_file|outfile|dumpfile)/i',
            '/(eval|base64_decode|gzinflate|str_rot13)/i',
            '/(file_get_contents|fopen|fwrite|include|require)/i',
            '/(system|exec|shell_exec|passthru|popen)/i'
        );

        foreach ($six_g_uri_patterns as $pattern) {
            if (preg_match($pattern, $request_uri)) {
                $this->block_6g_request('6g_request_uri', $pattern, $request_uri);
                return;
            }
        }

        // Check for forbidden files
        $forbidden_files = array(
            '/wp-config.php', '/wp-config.bak', '/wp-config.txt',
            '/.htaccess', '/.htpasswd', '/passwd', '/shadow',
            '/etc/passwd', '/etc/shadow', '/etc/hosts',
            '/proc/self/environ', '/proc/version', '/proc/cmdline',
            '/boot.ini', '/win.ini', '/system.ini',
            '/php.ini', '/.env', '/composer.json', '/package.json',
            '/wp-vcd.php', '/class.wp.php' // Common malware files
        );

        foreach ($forbidden_files as $file) {
            if (strpos($request_uri, $file) !== false) {
                $this->block_6g_request('6g_forbidden_file', $file, $request_uri);
                return;
            }
        }
    }

    private function check_6g_request_method() {
        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        $forbidden_methods = array('CONNECT', 'DEBUG', 'MOVE', 'PUT', 'TRACE', 'TRACK');

        if (in_array(strtoupper($method), $forbidden_methods)) {
            $this->block_6g_request('6g_request_method', $method, 'Forbidden HTTP Method');
        }

        // Check for oversized POST requests
        if ($method === 'POST') {
            $content_length = $_SERVER['CONTENT_LENGTH'] ?? 0;
            $max_post_size = $this->core->ms_get_option('max_post_size', 50) * 1024 * 1024; // Default 50MB

            if ($content_length > $max_post_size) {
                $this->block_6g_request('6g_large_post', $content_length, 'POST size too large');
            }
        }
    }

    private function check_6g_user_agent() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if (strlen($user_agent) > 2000) {
            $this->block_6g_request('6g_user_agent_length', 'oversized', $user_agent);
            return;
        }

        if (empty($user_agent)) {
            $this->block_6g_request('6g_empty_user_agent', 'empty', 'Empty User Agent');
            return;
        }

        $six_g_bad_bots = array(
            'archive.org', 'binlar', 'casper', 'checkpriv', 'choppy', 'clshttp',
            'cmsworld', 'diavol', 'dotbot', 'extract', 'feedfinder', 'flicky',
            'g00g1e', 'harvest', 'heritrix', 'httrack', 'kmccrew', 'loader',
            'miner', 'nikto', 'nutch', 'planetwork', 'postrank', 'purebot',
            'pycurl', 'python', 'seekerspider', 'siclab', 'skygrid', 'sqlmap',
            'sucker', 'turnit', 'vikspider', 'winhttp', 'xxxyy', 'youda',
            'zmeu', 'zune', 'wp-vcd', 'apiword'
        );

        foreach ($six_g_bad_bots as $bot) {
            if (stripos($user_agent, $bot) !== false) {
                $this->block_6g_request('6g_user_agent_bot', $bot, $user_agent);
                return;
            }
        }
    }

    private function check_6g_http_headers() {
        // Check referer
        if (isset($_SERVER['HTTP_REFERER'])) {
            $referer = $_SERVER['HTTP_REFERER'];

            if (strlen($referer) > 2000) {
                $this->block_6g_request('6g_referer_length', 'oversized', $referer);
                return;
            }

            $bad_referers = array('semalt.com', 'todaperfeita', 'kambasoft.com', 'savetubevideo.com');
            foreach ($bad_referers as $bad_ref) {
                if (stripos($referer, $bad_ref) !== false) {
                    $this->block_6g_request('6g_bad_referer', $bad_ref, $referer);
                    return;
                }
            }
        }

        // Check other headers for malicious content
        $headers_to_check = array(
            'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP',
            'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING',
            'HTTP_CONNECTION', 'HTTP_HOST'
        );

        foreach ($headers_to_check as $header) {
            if (isset($_SERVER[$header])) {
                $value = $_SERVER[$header];

                if (preg_match('/(\<|%3c).*script.*(\>|%3e)/i', $value)) {
                    $this->block_6g_request('6g_header_script', $header, $value);
                    return;
                }

                if (preg_match('/(union|select|insert|update|delete|drop)/i', $value)) {
                    $this->block_6g_request('6g_header_sql', $header, $value);
                    return;
                }

                if (preg_match('/(\.\./|\.\.\\\\)/i', $value)) {
                    $this->block_6g_request('6g_header_traversal', $header, $value);
                    return;
                }
            }
        }
    }

    public function basic_firewall_check() {
        if (!$this->should_apply_firewall_protection()) {
            return;
        }

        $this->check_basic_patterns();
        $this->check_file_inclusion();
        $this->check_code_injection();
    }

    private function check_basic_patterns() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';

        $basic_patterns = array(
            '/\.\./i',
            '/union.*select/i',
            '/<script/i',
            '/javascript:/i',
            '/eval\(/i',
            '/base64_decode/i',
            '/GLOBALS/i',
            '/_REQUEST/i'
        );

        foreach ($basic_patterns as $pattern) {
            if (preg_match($pattern, $request_uri . $query_string)) {
                $this->block_basic_request('basic_firewall', $pattern, $request_uri . $query_string);
                return;
            }
        }
    }

    private function check_file_inclusion() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';

        $lfi_patterns = array(
            '/etc\/passwd/',
            '/proc\/self\/environ/',
            '/boot\.ini/',
            '/win\.ini/',
            '/system\.ini/'
        );

        foreach ($lfi_patterns as $pattern) {
            if (preg_match($pattern, $request_uri . $query_string)) {
                $this->block_basic_request('file_inclusion', $pattern, 'File inclusion attempt');
                return;
            }
        }
    }

    private function check_code_injection() {
        $all_input = array_merge($_GET, $_POST);

        foreach ($all_input as $key => $value) {
            if (is_string($value)) {
                $dangerous_functions = array(
                    'eval', 'exec', 'system', 'shell_exec', 'passthru',
                    'file_get_contents', 'include', 'require'
                );

                foreach ($dangerous_functions as $func) {
                    if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/i', $value)) {
                        $this->block_basic_request('code_injection', $func, "Dangerous function in {$key}");
                        return;
                    }
                }
            }
        }
    }

    private function block_6g_request($rule_type, $pattern, $details) {
        $ip = $this->core->ms_get_user_ip();

        // Final whitelist check before blocking
        if ($this->is_ip_whitelisted($ip)) {
            $this->core->ms_log_security_event('6g_firewall_whitelist_bypass',
                "6G Firewall rule triggered but IP is whitelisted - Rule: {$rule_type}, IP: {$ip}",
                'low'
            );
            return;
        }

        $this->core->ms_log_security_event('6g_firewall_block',
            "6G Firewall blocked request - Rule: {$rule_type}, Pattern: {$pattern}",
            'high'
        );

        if ($this->core->ms_get_option('firewall_auto_block_ip', 1)) {
            $this->core->ms_block_ip($ip, "6G Firewall violation: {$rule_type}", 3600);
        }

        $this->send_block_response('6G Firewall', $rule_type);
    }

    private function block_basic_request($rule_type, $pattern, $details) {
        $ip = $this->core->ms_get_user_ip();

        // Final whitelist check before blocking
        if ($this->is_ip_whitelisted($ip)) {
            $this->core->ms_log_security_event('basic_firewall_whitelist_bypass',
                "Basic Firewall rule triggered but IP is whitelisted - Rule: {$rule_type}, IP: {$ip}",
                'low'
            );
            return;
        }

        $this->core->ms_log_security_event('basic_firewall_block',
            "Basic Firewall blocked request - Rule: {$rule_type}, Pattern: {$pattern}",
            'medium'
        );

        if ($this->core->ms_get_option('firewall_auto_block_ip', 1)) {
            $this->core->ms_block_ip($ip, "Basic Firewall violation: {$rule_type}", 1800);
        }

        $this->send_block_response('Basic Firewall', $rule_type);
    }

    private function send_block_response($firewall_type, $rule_type) {
        status_header(403);

        if ($this->core->ms_get_option('firewall_custom_block_page', 0)) {
            $this->show_custom_block_page($firewall_type, $rule_type);
        } else {
            die('Access Denied - Security Violation Detected');
        }
    }

    private function show_custom_block_page($firewall_type, $rule_type) {
        $block_message = $this->core->ms_get_option('firewall_block_message', 'Access Denied - Your request has been blocked by our security system.');

        echo '<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin: 50px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .error-code { font-size: 72px; color: #e74c3c; margin-bottom: 20px; }
        .error-message { font-size: 18px; color: #333; margin-bottom: 20px; }
        .error-details { font-size: 14px; color: #666; }
        .back-link { margin-top: 30px; }
        .back-link a { color: #3498db; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-code">403</div>
        <div class="error-message">' . esc_html($block_message) . '</div>
        <div class="error-details">
            Firewall: ' . esc_html($firewall_type) . '<br>
            Rule: ' . esc_html($rule_type) . '<br>
            Time: ' . date('Y-m-d H:i:s') . '<br>
            Reference ID: ' . uniqid() . '
        </div>
        <div class="back-link">
            <a href="javascript:history.back()">← Go Back</a>
        </div>
    </div>
</body>
</html>';
        exit;
    }

    public function track_user_login($user_login, $user) {
        $current_ip = $this->core->ms_get_user_ip();

        // Add to logged in users
        $logged_in_users = get_transient('ms_logged_in_users');
        if (!$logged_in_users) {
            $logged_in_users = array();
        }

        $logged_in_users[$user->ID] = array(
            'ip' => $current_ip,
            'timestamp' => time(),
            'user_login' => $user_login,
            'user_role' => $user->roles[0] ?? 'subscriber'
        );

        $session_timeout = $this->core->ms_get_option('whitelist_session_timeout', 3600);
        set_transient('ms_logged_in_users', $logged_in_users, $session_timeout);

        $this->core->ms_log_security_event('user_login_tracked',
            "User login tracked for whitelist: {$user_login} from IP: {$current_ip}",
            'low',
            $user->ID
        );

        // Refresh whitelist
        $this->init_whitelist();
    }

    public function track_user_logout() {
        $current_user = wp_get_current_user();
        if ($current_user->ID) {
            $logged_in_users = get_transient('ms_logged_in_users');
            if ($logged_in_users && isset($logged_in_users[$current_user->ID])) {
                unset($logged_in_users[$current_user->ID]);
                set_transient('ms_logged_in_users', $logged_in_users, 3600);

                $this->core->ms_log_security_event('user_logout_tracked',
                    "User logout tracked: {$current_user->user_login}",
                    'low',
                    $current_user->ID
                );
            }
        }
    }

    public function get_firewall_stats() {
        global $wpdb;

        $log_table = $wpdb->prefix . 'ms_security_log';

        $stats = array();

        $stats['6g_blocks_today'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE event_type = '6g_firewall_block'
             AND created_at > %s",
            date('Y-m-d 00:00:00')
        ));

        $stats['basic_blocks_today'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE event_type = 'basic_firewall_block'
             AND created_at > %s",
            date('Y-m-d 00:00:00')
        ));

        $stats['total_blocks_week'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE event_type IN ('6g_firewall_block', 'basic_firewall_block')
             AND created_at > %s",
            date('Y-m-d 00:00:00', strtotime('-7 days'))
        ));

        $stats['whitelist_bypasses'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE event_type LIKE '%whitelist_bypass%'
             AND created_at > %s",
            date('Y-m-d 00:00:00')
        ));

        $stats['top_blocked_rules'] = $wpdb->get_results($wpdb->prepare(
            "SELECT description, COUNT(*) as count
             FROM $log_table
             WHERE event_type IN ('6g_firewall_block', 'basic_firewall_block')
             AND created_at > %s
             GROUP BY description
             ORDER BY count DESC
             LIMIT 5",
            date('Y-m-d 00:00:00', strtotime('-7 days'))
        ));

        return $stats;
    }

    public function get_whitelist_info() {
        return array(
            'server_ips' => $this->server_ips,
            'logged_in_ips' => $this->logged_in_ips,
            'total_whitelisted' => count($this->whitelisted_ips),
            'last_refresh' => get_transient('ms_whitelist_last_refresh')
        );
    }
}