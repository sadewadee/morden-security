<?php
/**
 * Plugin Name: Morden Security
 * Plugin URI: https://github.com/sadewadee/morden-security
 * Description: Comprehensive WordPress security plugin with advanced firewall protection, brute force defense, security headers, file integrity monitoring, Hide Login URL, Database Prefix Changer, and File Permission Checker.
 * Version: 1.5.0
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
 *
 * @package MordenSecurity
 * @since 1.0.0
 */

namespace MordenSecurity;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('MORDEN_SECURITY_VERSION', '1.5.0');
define('MORDEN_SECURITY_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('MORDEN_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('MORDEN_SECURITY_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Backward compatibility constants (untuk existing code)
if (!defined('MS_VERSION')) {
    define('MS_VERSION', MORDEN_SECURITY_VERSION);
    define('MS_PLUGIN_PATH', MORDEN_SECURITY_PLUGIN_PATH);
    define('MS_PLUGIN_URL', MORDEN_SECURITY_PLUGIN_URL);
    define('MS_PLUGIN_BASENAME', MORDEN_SECURITY_PLUGIN_BASENAME);
}

/**
 * Main plugin class
 *
 * @since 1.0.0
 */
class Plugin {

    /**
     * Plugin instance
     *
     * @var Plugin
     */
    private static $instance = null;

    /**
     * Get plugin instance
     *
     * @return Plugin
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        add_action('plugins_loaded', array($this, 'init'));
    }

    /**
     * Initialize plugin
     */
    public function init() {
        load_plugin_textdomain('morden-security', false, dirname(plugin_basename(__FILE__)) . '/languages');

        $this->include_files();
        $this->init_components();
    }

    /**
     * Include required files
     */
    private function include_files() {
        // Core files dengan namespace support
        $files = array(
            'includes/class-ms-database.php',
            'includes/class-ms-core.php',
            'includes/class-ms-permissions.php',
            'includes/class-ms-version.php',
            'includes/class-ms-security.php',
            'includes/class-ms-customizer.php',
            'includes/class-ms-firewall.php',
            'includes/class-ms-rate-limiter.php',
            'includes/class-ms-integrity-checker.php',
            'includes/class-ms-logger.php'
        );

        foreach ($files as $file) {
            $file_path = MORDEN_SECURITY_PLUGIN_PATH . $file;
            if (file_exists($file_path)) {
                require_once $file_path;
            }
        }

        // Admin files
        if (is_admin()) {
            $admin_file = MORDEN_SECURITY_PLUGIN_PATH . 'includes/class-ms-admin.php';
            if (file_exists($admin_file)) {
                require_once $admin_file;
            }
        }
    }

    /**
     * Initialize components
     */
    private function init_components() {
        // Initialize dengan namespace awareness
        if (class_exists('MS_Core')) {
            \MS_Core::get_instance();
        }

        if (class_exists('MS_Security')) {
            \MS_Security::get_instance();
        }

        if (class_exists('MS_Firewall')) {
            $firewall = \MS_Firewall::get_instance();
            add_action('wp_login', array($firewall, 'track_user_login'), 10, 2);
        }

        if (class_exists('MS_Customizer')) {
            \MS_Customizer::get_instance();
        }

        if (is_admin() && class_exists('MS_Admin')) {
            \MS_Admin::get_instance();
        }
    }

    /**
     * Plugin activation
     */
    public function activate() {
        // Activation logic dengan namespace support
        if (!class_exists('MS_Database')) {
            $database_file = MORDEN_SECURITY_PLUGIN_PATH . 'includes/class-ms-database.php';
            if (file_exists($database_file)) {
                require_once $database_file;
            }
        }

        if (class_exists('MS_Database')) {
            \MS_Database::create_all_tables();
        }

        // Set default options
        $this->set_default_options();
        $this->create_security_rules();
        $this->create_backup_directory();
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        wp_clear_scheduled_hook('ms_cleanup_login_attempts');
        wp_clear_scheduled_hook('ms_security_scan');
        wp_clear_scheduled_hook('ms_integrity_check');
        wp_cache_flush();
    }

    /**
     * Set default plugin options
     */
    private function set_default_options() {
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
            'enable_firewall' => 1,
            'firewall_auto_block_ip' => 1,
            'firewall_custom_block_page' => 1,
            'firewall_block_message' => 'Access Denied - Your request has been blocked by Morden Security protection system.',
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
    }

    /**
     * Create security rules
     */
    private function create_security_rules() {
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';

        if (!file_exists($htaccess_file)) {
            $htaccess_content = "# Morden Security - Upload Protection\n";
            $htaccess_content .= "Options -Indexes\n";
            $htaccess_content .= "<Files *.php>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";

            file_put_contents($htaccess_file, $htaccess_content);
        }
    }

    /**
     * Create backup directory
     */
    private function create_backup_directory() {
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

// Initialize plugin
Plugin::get_instance();