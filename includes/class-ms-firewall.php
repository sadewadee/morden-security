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
        if ($this->core->ms_get_option('enable_firewall', 1)) {
            add_action('init', array($this, 'apply_firewall_protection'), 1);
        }

        add_action('wp_login', array($this, 'track_user_login'), 10, 2);
        add_action('wp_logout', array($this, 'track_user_logout'));
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
        $last_refresh = get_transient('ms_whitelist_last_refresh');
        if ($last_refresh && (time() - $last_refresh) < 300) {
            return;
        }

        $this->init_whitelist();
        set_transient('ms_whitelist_last_refresh', time(), 300);
    }

    private function get_server_ips() {
        $server_ips = array();

        if (isset($_SERVER['SERVER_ADDR']) && !empty($_SERVER['SERVER_ADDR'])) {
            $server_ips[] = $_SERVER['SERVER_ADDR'];
        }

        $server_name = $_SERVER['SERVER_NAME'] ?? $_SERVER['HTTP_HOST'] ?? '';
        if (!empty($server_name)) {
            $server_ip = gethostbyname($server_name);
            if ($server_ip && $server_ip !== $server_name && filter_var($server_ip, FILTER_VALIDATE_IP)) {
                $server_ips[] = $server_ip;
            }
        }

        $localhost_ips = array(
            '127.0.0.1', '::1', 'localhost',
            '192.168.1.1', '10.0.0.1', '172.16.0.1'
        );
        $server_ips = array_merge($server_ips, $localhost_ips);

        $proxy_headers = array(
            'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP',
            'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED'
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

        $cloudflare_ranges = array(
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        );

        foreach ($cloudflare_ranges as $range) {
            if ($this->ip_in_range($current_ip, $range)) {
                $hosting_ips[] = $current_ip;
                break;
            }
        }

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

        $logged_in_users = get_transient('ms_logged_in_users');
        if (!$logged_in_users) {
            $logged_in_users = array();
        }

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

        $current_time = time();
        $session_timeout = $this->core->ms_get_option('whitelist_session_timeout', 3600);

        foreach ($logged_in_users as $user_id => $data) {
            if (($current_time - $data['timestamp']) < $session_timeout) {
                $logged_in_ips[] = $data['ip'];
            } else {
                unset($logged_in_users[$user_id]);
            }
        }

        set_transient('ms_logged_in_users', $logged_in_users, $session_timeout);

        return array_unique($logged_in_ips);
    }

    private function get_admin_ips() {
        $admin_ips = array();

        $admin_ip_list = $this->core->ms_get_option('admin_whitelist_ips', '');
        if (!empty($admin_ip_list)) {
            $admin_ips = array_map('trim', explode("\n", $admin_ip_list));
            $admin_ips = array_filter($admin_ips, function($ip) {
                return filter_var(trim($ip), FILTER_VALIDATE_IP);
            });
        }

        if (is_user_logged_in() && current_user_can('manage_options')) {
            $current_ip = $this->core->ms_get_user_ip();
            if (!in_array($current_ip, $admin_ips) && filter_var($current_ip, FILTER_VALIDATE_IP)) {
                $admin_ips[] = $current_ip;

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
        if (strpos($range, '/') !== false) {
            list($ip, $mask) = explode('/', $range);
            return filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($mask) && $mask >= 0 && $mask <= 32;
        }

        if (strpos($range, '*') !== false) {
            $pattern = str_replace('*', '([0-9]{1,3})', preg_quote($range, '/'));
            return preg_match('/^' . $pattern . '$/', '192.168.1.1') !== false;
        }

        return false;
    }

    public function is_ip_whitelisted($ip) {
        $this->refresh_whitelist();

        if (in_array($ip, $this->whitelisted_ips)) {
            return true;
        }

        $ip_ranges = $this->core->ms_get_option('whitelist_ip_ranges', '');
        if (!empty($ip_ranges)) {
            $ranges = array_map('trim', explode("\n", $ip_ranges));
            foreach ($ranges as $range) {
                if ($this->ip_in_range($ip, $range)) {
                    return true;
                }
            }
        }

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
            list($subnet, $mask) = explode('/', $range);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);

            if ($ip_long === false || $subnet_long === false) {
                return false;
            }

            $mask_long = -1 << (32 - (int)$mask);
            return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
        } else {
            if (strpos($range, '*') !== false) {
                $pattern = str_replace('*', '([0-9]{1,3})', preg_quote($range, '/'));
                return preg_match('/^' . $pattern . '$/', $ip) === 1;
            }
            return $ip === $range;
        }
    }

    private function should_apply_firewall_protection() {
        $current_ip = $this->core->ms_get_user_ip();

        if ($this->is_ip_whitelisted($current_ip)) {
            return false;
        }

        if (defined('DOING_AJAX') && DOING_AJAX && is_user_logged_in()) {
            return false;
        }

        if (defined('DOING_CRON') && DOING_CRON) {
            return false;
        }

        if (is_admin() && is_user_logged_in() && current_user_can('manage_options')) {
            return false;
        }

        if (defined('REST_REQUEST') && REST_REQUEST && is_user_logged_in()) {
            return false;
        }

        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST && is_user_logged_in()) {
            return false;
        }

        return true;
    }

    public function apply_firewall_protection() {
        if (!$this->should_apply_firewall_protection()) {
            return;
        }

        $this->check_query_string_patterns();
        $this->check_request_uri_patterns();
        $this->check_request_method_patterns();
        $this->check_user_agent_patterns();
        $this->check_http_header_patterns();
        $this->check_post_data_patterns();
        $this->check_file_upload_patterns();
    }

    private function check_query_string_patterns() {
        $query_string = $_SERVER['QUERY_STRING'] ?? '';

        if (empty($query_string)) {
            return;
        }

        $ms_firewall_patterns = array(
            // Advanced SQL injection patterns
            '/(union|select|insert|update|delete|drop|create|alter|exec|execute)\s*[\(\[]/i',
            '/(information_schema|mysql\.|sys\.|performance_schema)/i',
            '/(concat|load_file|outfile|dumpfile|into\s+outfile)/i',
            '/(benchmark|sleep|get_lock|release_lock|user\(\)|version\(\))/i',
            '/(having|group\s+by|order\s+by|limit|offset)\s+/i',

            // Advanced XSS patterns
            '/(<|%3c)(script|iframe|object|embed|applet|meta|link|style|img|svg|form|input|button)(\s|%20|>|%3e)/i',
            '/(javascript|vbscript|data|livescript|mocha|jscript)(\s*:|%3a)/i',
            '/(onload|onerror|onclick|onmouseover|onfocus|onblur|onchange|onsubmit)(\s*=|%3d)/i',
            '/(document\.|window\.|eval\(|alert\(|confirm\(|prompt\(|setTimeout\(|setInterval\()/i',
            '/(expression\(|url\(|@import|behaviour:)/i',

            // File inclusion and traversal
            '/(\.\./|\.\.\\\\|\.\.%2f|\.\.%5c){2,}/i',
            '/(etc\/passwd|etc\/shadow|etc\/hosts|proc\/self\/environ|proc\/version|proc\/cmdline)/i',
            '/(boot\.ini|win\.ini|system\.ini|php\.ini|\.htaccess|\.htpasswd|wp-config\.php)/i',
            '/(file:\/\/|php:\/\/|ftp:\/\/|data:\/\/|expect:\/\/|zip:\/\/|compress\.zlib:\/\/)/i',

            // Code injection patterns
            '/(eval|base64_decode|gzinflate|str_rot13|assert|preg_replace.*\/e|create_function)/i',
            '/(file_get_contents|file_put_contents|fopen|fwrite|include|require|include_once|require_once)/i',
            '/(system|exec|shell_exec|passthru|popen|proc_open|escapeshellcmd|escapeshellarg)/i',
            '/(call_user_func|call_user_func_array|register_shutdown_function|register_tick_function)/i',

            // WordPress specific
            '/(wp-config|wp-admin\/includes|wp-includes\/|xmlrpc\.php)/i',
            '/(thumbs?(_editor|open)?|tim(thumb)?|phpthumb)\.php/i',
            '/(revslider|layerslider|masterslider)/i',

            // Protocol manipulation and null bytes
            '/(%00|%01|%02|%03|%04|%05|%06|%07|%08|%09|%0a|%0b|%0c|%0d|%0e|%0f)/i',
            '/(\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x09|\x0a|\x0b|\x0c|\x0d|\x0e|\x0f)/i',

            // Large payloads and suspicious globals
            '/([a-z0-9]{2000,})/i',
            '/(GLOBALS|REQUEST|_GET|_POST|_COOKIE|_SESSION|_SERVER|_FILES|_ENV)\[/i',

            // Advanced evasion techniques
            '/(chr\(|char\(|ascii\(|ord\(|hex\(|unhex\()/i',
            '/(0x[0-9a-f]+|\\\\x[0-9a-f]+)/i'
        );

        foreach ($ms_firewall_patterns as $pattern) {
            if (preg_match($pattern, $query_string)) {
                $this->block_request('ms_firewall_query_string', $pattern, $query_string);
                return;
            }
        }
    }

    private function check_request_uri_patterns() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';

        if (empty($request_uri)) {
            return;
        }

        $ms_firewall_uri_patterns = array(
            // Directory traversal
            '/(\.\./|\.\.\\\\|\.\.%2f|\.\.%5c){2,}/i',
            '/(\.\.\/){3,}/i',
            '/(\.\./){3,}/i',

            // System files
            '/(etc\/passwd|etc\/shadow|proc\/self\/environ|boot\.ini|win\.ini|system\.ini)/i',
            '/(php\.ini|\.htaccess|\.htpasswd|\.env|composer\.json|package\.json)/i',

            // Executable and dangerous files
            '/\.(aspx?|bash|bat|bak|cfg|cgi|cmd|com|dll|exe|hta|ini|jsp|log|mdb|out|php\d?|pif|scr|sh|sql|swp|tar|rar|zip|war|ear)(\?|$)/i',

            // WordPress specific files
            '/\/(wp-config|wp-admin\/includes|wp-includes\/|xmlrpc)\.php/i',
            '/\/(install|upgrade|setup|config|admin|test|demo|backup|dump)\.php/i',

            // Malicious scripts and shells
            '/\/(shell|cmd|command|backdoor|webshell|c99|r57|bypass|exploit|hack)\.php/i',
            '/\/(phpinfo|phpmyadmin|adminer|sql|database|mysql|postgres)\.php/i',

            // Code patterns in URI
            '/(base64_encode|base64_decode|eval|exec|system|shell_exec|passthru)/i',
            '/(union|select|insert|update|delete|drop|create|alter)/i',

            // Protocol manipulation
            '/(https?|ftp|php|file|data|expect|zip|compress|glob):/i',

            // Null bytes and control characters
            '/(%00|%01|%02|%03|%04|%05|%06|%07|%08|%09|%0a|%0b|%0c|%0d|%0e|%0f)/i',

            // Large payloads
            '/([a-z0-9]{1500,})/i',

            // Suspicious parameters
            '/(\?|&)(cmd|exec|system|shell|eval|base64|file|path|dir|url|src|data|include|require)=/i',

            // Common attack patterns
            '/(\<|%3c)(script|iframe|object|embed|applet)(\s|%20|\>|%3e)/i',
            '/(javascript|vbscript|data|livescript):/i',

            // WordPress vulnerabilities
            '/(timthumb|thumb\.php|phpthumb|thumb_editor)/i',
            '/(revslider|layerslider|masterslider|slider_revolution)/i',
            '/(wp-vcd|class\.wp\.php|hello\.php)/i'
        );

        foreach ($ms_firewall_uri_patterns as $pattern) {
            if (preg_match($pattern, $request_uri)) {
                $this->block_request('ms_firewall_request_uri', $pattern, $request_uri);
                return;
            }
        }
    }

    private function check_request_method_patterns() {
        $method = $_SERVER['REQUEST_METHOD'] ?? '';

        $forbidden_methods = array(
            'CONNECT', 'DEBUG', 'MOVE', 'PUT', 'TRACE', 'TRACK', 'DELETE',
            'PATCH', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'LOCK', 'UNLOCK',
            'SEARCH', 'SUBSCRIBE', 'UNSUBSCRIBE', 'NOTIFY', 'POLL', 'BMOVE',
            'BDELETE', 'BPROPFIND', 'BPROPPATCH', 'BCOPY', 'BDELETE', 'BMOVE'
        );

        if (in_array(strtoupper($method), $forbidden_methods)) {
            $this->block_request('ms_firewall_request_method', $method, 'Forbidden HTTP Method');
            return;
        }

        if ($method === 'POST') {
            $content_length = $_SERVER['CONTENT_LENGTH'] ?? 0;
            $max_post_size = $this->core->ms_get_option('max_post_size', 50) * 1024 * 1024;

            if ($content_length > $max_post_size) {
                $this->block_request('ms_firewall_large_post', $content_length, 'POST size too large');
                return;
            }
        }
    }

    private function check_user_agent_patterns() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if (strlen($user_agent) > 2000) {
            $this->block_request('ms_firewall_user_agent_length', 'oversized', $user_agent);
            return;
        }

        if (empty($user_agent)) {
            $this->block_request('ms_firewall_empty_user_agent', 'empty', 'Empty User Agent');
            return;
        }

        $ms_firewall_bad_agents = array(
            // Security scanners and vulnerability tools
            'acunetix', 'appscan', 'arachni', 'burpsuite', 'netsparker', 'nikto',
            'nmap', 'openvas', 'paros', 'sqlmap', 'vega', 'w3af', 'webscarab',
            'wpscan', 'skipfish', 'grabber', 'dirbuster', 'dirb', 'gobuster',
            'masscan', 'zmap', 'shodan', 'censys', 'zgrab', 'nuclei',

            // Malicious bots and scrapers
            'binlar', 'casper', 'checkpriv', 'choppy', 'clshttp', 'cmsworld',
            'diavol', 'dotbot', 'extract', 'feedfinder', 'flicky', 'g00g1e',
            'harvest', 'heritrix', 'httrack', 'kmccrew', 'loader', 'miner',
            'nutch', 'planetwork', 'postrank', 'purebot', 'pycurl', 'python',
            'seekerspider', 'siclab', 'skygrid', 'sucker', 'turnit', 'vikspider',
            'winhttp', 'xxxyy', 'youda', 'zmeu', 'zune', 'archive.org',

            // Automated tools
            'curl', 'wget', 'libwww', 'lwp-trivial', 'urllib', 'java/', 'go-http-client',
            'httpclient', 'okhttp', 'python-requests', 'python-urllib',

            // Malware and backdoors
            'wp-vcd', 'backdoor', 'shell', 'webshell', 'c99', 'r57', 'bypass',
            'exploit', 'payload', 'trojan', 'virus', 'malware', 'botnet',

            // Spam and SEO bots
            'semalt', 'kambasoft', 'savetubevideo', 'buttons-for-website',
            'sharebutton', 'soundfrost', 'srecorder', 'softomix', 'openmediasoft',

            // Additional bad bots
            '360spider', 'acapbot', 'acoonbot', 'asterias', 'attackbot', 'backdorbot',
            'becomebot', 'blackwidow', 'blekkobot', 'blexbot', 'blowfish', 'bullseye',
            'bunnys', 'butterfly', 'careerbot', 'cheesebot', 'cherrypick', 'chinaclaw',
            'copernic', 'copyrightcheck', 'cosmos', 'crescent', 'cy_cho', 'datacha',
            'demon', 'dittospyder', 'dotnetdotcom', 'dumbot', 'emailcollector',
            'emailsiphon', 'emailwolf', 'exabot', 'eyenetie', 'flaming', 'flashget'
        );

        foreach ($ms_firewall_bad_agents as $agent) {
            if (stripos($user_agent, $agent) !== false) {
                $this->block_request('ms_firewall_user_agent_bot', $agent, $user_agent);
                return;
            }
        }

        $suspicious_ua_patterns = array(
            '/script/i',
            '/eval\(/i',
            '/base64/i',
            '/union.*select/i',
            '/\<.*\>/i',
            '/(javascript|vbscript):/i',
            '/(onload|onerror|onclick)=/i'
        );

        foreach ($suspicious_ua_patterns as $pattern) {
            if (preg_match($pattern, $user_agent)) {
                $this->block_request('ms_firewall_user_agent_suspicious', $pattern, $user_agent);
                return;
            }
        }
    }

    private function check_http_header_patterns() {
        $headers_to_check = array(
            'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP',
            'HTTP_REFERER', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE',
            'HTTP_ACCEPT_ENCODING', 'HTTP_CONNECTION', 'HTTP_HOST',
            'HTTP_AUTHORIZATION', 'HTTP_COOKIE', 'HTTP_X_REQUESTED_WITH',
            'HTTP_ORIGIN', 'HTTP_X_FORWARDED_PROTO', 'HTTP_X_FORWARDED_HOST'
        );

        foreach ($headers_to_check as $header) {
            if (isset($_SERVER[$header])) {
                $value = $_SERVER[$header];

                if (preg_match('/(\<|%3c).*script.*(\>|%3e)/i', $value)) {
                    $this->block_request('ms_firewall_header_script', $header, $value);
                    return;
                }

                if (preg_match('/(union|select|insert|update|delete|drop)/i', $value)) {
                    $this->block_request('ms_firewall_header_sql', $header, $value);
                    return;
                }

                if (preg_match('/(\.\./|\.\.\\\\)/i', $value)) {
                    $this->block_request('ms_firewall_header_traversal', $header, $value);
                    return;
                }

                if (preg_match('/(%00|%01|%02|%03|%04|%05|%06|%07)/i', $value)) {
                    $this->block_request('ms_firewall_header_null_byte', $header, $value);
                    return;
                }

                if (preg_match('/(eval|base64_decode|exec|system|shell_exec)/i', $value)) {
                    $this->block_request('ms_firewall_header_code_injection', $header, $value);
                    return;
                }
            }
        }

        if (isset($_SERVER['HTTP_REFERER'])) {
            $referer = $_SERVER['HTTP_REFERER'];

            if (strlen($referer) > 2000) {
                $this->block_request('ms_firewall_referer_length', 'oversized', $referer);
                return;
            }

            $bad_referers = array(
                'semalt.com', 'todaperfeita', 'kambasoft.com', 'savetubevideo.com',
                'buttons-for-website.com', 'sharebutton.net', 'soundfrost.org',
                'srecorder.com', 'softomix.com', 'openmediasoft.com',
                'econom.co', 'guardlink.org', 'hongfanji.com', 'iedit.ilovevitaly.com',
                'ilovevitaly.co', 'ilovevitaly.com', 'ilovevitaly.info', 'ilovevitaly.org',
                'ilovevitaly.ru', 'iskalko.ru', 'luxup.ru', 'myftpupload.com',
                'o-o-6-o-o.com', 'o-o-8-o-o.com', 'ranksonic.info', 'ranksonic.org'
            );

            foreach ($bad_referers as $bad_ref) {
                if (stripos($referer, $bad_ref) !== false) {
                    $this->block_request('ms_firewall_bad_referer', $bad_ref, $referer);
                    return;
                }
            }
        }
    }

    private function check_post_data_patterns() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return;
        }

        $post_data = file_get_contents('php://input');

        if (empty($post_data)) {
            return;
        }

        $ms_firewall_post_patterns = array(
            '/(union|select|insert|update|delete|drop|create|alter)\s*[\(\[]/i',
            '/(information_schema|mysql\.|sys\.|performance_schema)/i',
            '/(concat|load_file|outfile|dumpfile|into\s+outfile)/i',
            '/(<|%3c)(script|iframe|object|embed|applet)(\s|%20|>|%3e)/i',
            '/(javascript|vbscript|onload|onerror|onclick)(\s*:|%3a)/i',
            '/(eval|base64_decode|gzinflate|str_rot13|assert)/i',
            '/(file_get_contents|file_put_contents|fopen|fwrite)/i',
            '/(system|exec|shell_exec|passthru|popen)/i',
            '/(\.\./|\.\.\\\\|\.\.%2f|\.\.%5c){2,}/i',
            '/(etc\/passwd|etc\/shadow|proc\/self\/environ)/i',
            '/(%00|%01|%02|%03|%04|%05|%06|%07)/i'
        );

        foreach ($ms_firewall_post_patterns as $pattern) {
            if (preg_match($pattern, $post_data)) {
                $this->block_request('ms_firewall_post_data', $pattern, 'Malicious POST data');
                return;
            }
        }
    }

    private function check_file_upload_patterns() {
        if (empty($_FILES)) {
            return;
        }

        foreach ($_FILES as $file) {
            if (!isset($file['name']) || !isset($file['tmp_name'])) {
                continue;
            }

            $filename = $file['name'];
            $tmp_name = $file['tmp_name'];

            $dangerous_extensions = array(
                'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'pht',
                'asp', 'aspx', 'jsp', 'jspx', 'cfm', 'cfc',
                'pl', 'py', 'rb', 'sh', 'bash', 'bat', 'cmd',
                'exe', 'com', 'scr', 'pif', 'vbs', 'js',
                'jar', 'war', 'ear', 'htaccess', 'htpasswd'
            );

            $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

            if (in_array($file_ext, $dangerous_extensions)) {
                $this->block_request('ms_firewall_file_upload', $file_ext, "Dangerous file upload: {$filename}");
                return;
            }

            if (is_uploaded_file($tmp_name) && filesize($tmp_name) > 0) {
                $file_content = file_get_contents($tmp_name, false, null, 0, 1024);

                $malicious_patterns = array(
                    '/<\?php/i',
                    '/eval\(/i',
                    '/base64_decode/i',
                    '/system\(/i',
                    '/exec\(/i',
                    '/shell_exec/i',
                    '/passthru\(/i',
                    '/file_get_contents\(/i',
                    '/fopen\(/i',
                    '/include\(/i',
                    '/require\(/i'
                );

                foreach ($malicious_patterns as $pattern) {
                    if (preg_match($pattern, $file_content)) {
                        $this->block_request('ms_firewall_file_content', $pattern, "Malicious file content: {$filename}");
                        return;
                    }
                }
            }
        }
    }

    private function block_request($rule_type, $pattern, $details) {
        $ip = $this->core->ms_get_user_ip();

        if ($this->is_ip_whitelisted($ip)) {
            $this->core->ms_log_security_event('ms_firewall_whitelist_bypass',
                "Morden Security Firewall rule triggered but IP is whitelisted - Rule: {$rule_type}, IP: {$ip}",
                'low'
            );
            return;
        }

        $this->core->ms_log_security_event('ms_firewall_block',
            "Morden Security Firewall blocked request - Rule: {$rule_type}, Pattern: {$pattern}",
            'high'
        );

        if ($this->core->ms_get_option('firewall_auto_block_ip', 1)) {
            $this->core->ms_block_ip($ip, "MS Firewall violation: {$rule_type}", 3600);
        }

        status_header(403);

        if ($this->core->ms_get_option('firewall_custom_block_page', 0)) {
            $this->show_custom_block_page($rule_type);
        } else {
            die('Access Denied - Morden Security Protection Active');
        }
    }

    private function show_custom_block_page($rule_type) {
        $block_message = $this->core->ms_get_option('firewall_block_message', 'Access Denied - Your request has been blocked by Morden Security protection system.');

        echo '<!DOCTYPE html>
<html>
<head>
    <title>Access Denied - Morden Security</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .container { max-width: 600px; margin: 0 auto; background: rgba(255,255,255,0.1); padding: 40px; border-radius: 16px; backdrop-filter: blur(10px); }
        .error-code { font-size: 72px; margin-bottom: 20px; }
        .error-message { font-size: 18px; margin-bottom: 20px; }
        .error-details { font-size: 14px; opacity: 0.8; }
        .back-link { margin-top: 30px; }
        .back-link a { color: white; text-decoration: none; border: 1px solid white; padding: 10px 20px; border-radius: 8px; }
        .logo { font-size: 24px; font-weight: bold; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️ Morden Security</div>
        <div class="error-code">403</div>
        <div class="error-message">' . esc_html($block_message) . '</div>
        <div class="error-details">
            Protection: Morden Security Firewall<br>
            Rule: ' . esc_html($rule_type) . '<br>
            Time: ' . date('Y-m-d H:i:s') . '<br>
            Reference ID: MS-' . uniqid() . '
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

        $stats['firewall_blocks_today'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE event_type = 'ms_firewall_block'
             AND created_at > %s",
            date('Y-m-d 00:00:00')
        ));

        $stats['firewall_blocks_week'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE event_type = 'ms_firewall_block'
             AND created_at > %s",
            date('Y-m-d 00:00:00', strtotime('-7 days'))
        ));

        $stats['whitelist_bypasses'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE event_type = 'ms_firewall_whitelist_bypass'
             AND created_at > %s",
            date('Y-m-d 00:00:00')
        ));

        $stats['top_blocked_rules'] = $wpdb->get_results($wpdb->prepare(
            "SELECT description, COUNT(*) as count
             FROM $log_table
             WHERE event_type = 'ms_firewall_block'
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
