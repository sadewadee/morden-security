<?php
/**
 * Plugin Name: Morden Security
 * Plugin URI: https://github.com/sadewadee/morden-security
 * Description: Comprehensive WordPress security plugin with advanced firewall protection, brute force defense, security headers, file integrity monitoring, Hide Login URL, Database Prefix Changer, and File Permission Checker.
 * Version: 1.4.0
 * Author: Mordenhost Team
 * Author URI: https://mordenhost.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: morden-security
 * Domain Path: /languages
 * Requires at least: 6.1
 * Tested up to: 6.7.2
 * Requires PHP: 7.4
 * Network: false
 */

if (!defined('ABSPATH')) {
    exit;
}

define('MS_VERSION', '1.4.0');
define('MS_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('MS_PLUGIN_URL', plugin_dir_url(__FILE__));
define('MS_PLUGIN_BASENAME', plugin_basename(__FILE__));

class Morden_Security {

    private static $instance = null;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        register_activation_hook(__FILE__, array($this, 'ms_activate'));
        register_deactivation_hook(__FILE__, array($this, 'ms_deactivate'));

        add_action('plugins_loaded', array($this, 'ms_init'));
    }

    public function ms_init() {
        load_plugin_textdomain('morden-security', false, dirname(plugin_basename(__FILE__)) . '/languages');

        $this->ms_include_files();
        $this->ms_init_components();
    }

    private function ms_include_files() {
        // Core files - harus dimuat terlebih dahulu
        require_once MS_PLUGIN_PATH . 'includes/class-ms-database.php';
        require_once MS_PLUGIN_PATH . 'includes/class-ms-core.php';

        // Optional files - cek keberadaan sebelum include
        $optional_files = array(
            'includes/class-ms-permissions.php',
            'includes/class-ms-version.php',
            'includes/class-ms-security.php',
            'includes/class-ms-customizer.php', // FIXED: Ganti dari customization ke customizer
            'includes/class-ms-firewall.php',
            'includes/class-ms-rate-limiter.php',
            'includes/class-ms-logger.php'
        );

        foreach ($optional_files as $file) {
            $file_path = MS_PLUGIN_PATH . $file;
            if (file_exists($file_path)) {
                require_once $file_path;
            }
        }

        if (is_admin()) {
            require_once MS_PLUGIN_PATH . 'includes/class-ms-admin.php';
        }
    }

    private function ms_init_components() {
        MS_Core::get_instance();

        // Initialize components yang ada
        if (class_exists('MS_Security')) {
            MS_Security::get_instance();
        }

        if (class_exists('MS_Firewall')) {
            $firewall = MS_Firewall::get_instance();
            add_action('wp_login', array($firewall, 'track_user_login'), 10, 2);
        }

        if (class_exists('MS_Customizer')) { // FIXED: Ganti dari MS_Customization ke MS_Customizer
            MS_Customizer::get_instance();
        }

        if (class_exists('MS_Logger')) {
            MS_Logger::get_instance();
        }

        if (is_admin() && class_exists('MS_Admin')) {
            MS_Admin::get_instance();
        }
    }

    public function ms_activate() {
        $default_options = array(
            'disable_file_editor' => 1,
            'force_ssl' => 1,
            'disable_xmlrpc' => 1,
            'limit_login_attempts' => 1,
            'max_login_attempts' => 5,
            'lockout_duration' => 1800,
            'enable_security_headers' => 1,
            'hide_wp_version' => 1,
            'remove_wp_credit' => 1,
            'hide_wp_logo' => 1,
            'hide_admin_bar' => 1,
            'turnstile_enabled' => 0,
            'turnstile_site_key' => '',
            'turnstile_secret_key' => '',
            'enable_2fa' => 0,
            'block_suspicious_requests' => 1,
            'enable_firewall' => 1,
            'scan_uploads' => 1,
            'max_logs' => 1000,
            'max_days_retention' => 30,
            'enable_geolocation' => 1,
            'block_php_uploads' => 1,
            'disable_pingbacks' => 1,
            'enable_bot_protection' => 1,
            'block_author_scans' => 1,
            'enable_file_integrity' => 1,
            'hide_login_url' => 0,
            'custom_login_url' => 'secure-login',
            'firewall_auto_block_ip' => 1,
            'firewall_custom_block_page' => 1,
            'firewall_block_message' => 'Access Denied - Your request has been blocked by Morden Security protection system.',
            'admin_whitelist_ips' => '',
            'custom_whitelist_ips' => '',
            'whitelist_ip_ranges' => ''
        );

        // Auto-add current admin IP
        if (is_admin() && current_user_can('manage_options')) {
            $current_ip = $_SERVER['REMOTE_ADDR'] ?? '';
            if (!empty($current_ip)) {
                $default_options['admin_whitelist_ips'] = $current_ip;
            }
        }

        add_option('ms_settings', $default_options);

        MS_Database::create_all_tables();
        $this->ms_set_default_security_rules();
        $this->ms_create_backup_directory();
    }

    public function ms_deactivate() {
        wp_clear_scheduled_hook('ms_cleanup_login_attempts');
        wp_clear_scheduled_hook('ms_security_scan');
        wp_clear_scheduled_hook('ms_integrity_check');

        wp_cache_flush();
    }

    private function ms_set_default_security_rules() {
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';

        if (!file_exists($htaccess_file)) {
            $htaccess_content = "# Morden Security - Upload Protection\n";
            $htaccess_content .= "Options -Indexes\n";
            $htaccess_content .= "<Files *.php>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.phtml>\n";
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

            file_put_contents($htaccess_file, $htaccess_content);
        }
    }

    private function ms_create_backup_directory() {
        $backup_dir = WP_CONTENT_DIR . '/ms-backups';
        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);

            $htaccess_content = "# Morden Security - Backup Protection\n";
            $htaccess_content .= "Order deny,allow\n";
            $htaccess_content .= "Deny from all\n";
            file_put_contents($backup_dir . '/.htaccess', $htaccess_content);
        }
    }
}

Morden_Security::get_instance();
