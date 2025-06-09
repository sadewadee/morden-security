<?php
/**
 * Plugin Name: Morden Security
 * Plugin URI: https://mordenhost.com/morden-security/
 * Description: Advanced WordPress security plugin with comprehensive protection features including brute force protection, security headers, login customization, and Cloudflare Turnstile integration.
 * Version: 1.0.1-beta
 * Author: Morden Security Team
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

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('MS_VERSION', '1.0.1-beta');
define('MS_PLUGIN_URL', plugin_dir_url(__FILE__));
define('MS_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('MS_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Main plugin class
class MS_Morden_Security {

    private static $instance = null;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action('plugins_loaded', array($this, 'ms_init'));
        register_activation_hook(__FILE__, array($this, 'ms_activate'));
        register_deactivation_hook(__FILE__, array($this, 'ms_deactivate'));
    }

    public function ms_init() {
        // Load text domain
        load_plugin_textdomain('morden-security', false, dirname(MS_PLUGIN_BASENAME) . '/languages');

        // Include required files
        $this->ms_include_files();

        // Initialize components
        MS_Core::get_instance();
        MS_Security::get_instance();

        if (is_admin()) {
            MS_Admin::get_instance();
        }

        MS_Customizer::get_instance();
    }

    private function ms_include_files() {
        require_once MS_PLUGIN_PATH . 'includes/class-ms-core.php';
        require_once MS_PLUGIN_PATH . 'includes/class-ms-security.php';
        require_once MS_PLUGIN_PATH . 'includes/class-ms-customizer.php';

        if (is_admin()) {
            require_once MS_PLUGIN_PATH . 'includes/class-ms-admin.php';
        }
    }

    public function ms_activate() {
        // Create default options
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
            'enable_geolocation' => 1
        );

        add_option('ms_settings', $default_options);

        // Create necessary tables
        $this->ms_create_tables();

        // Set default security rules
        $this->ms_set_default_security_rules();
    }

    public function ms_deactivate() {
        // Clean up scheduled events
        wp_clear_scheduled_hook('ms_cleanup_login_attempts');
        wp_clear_scheduled_hook('ms_security_scan');
    }

    private function ms_create_tables() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        // Login attempts table
        $table_name = $wpdb->prefix . 'ms_login_attempts';
        $sql = "CREATE TABLE $table_name (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            username varchar(255) DEFAULT NULL,
            attempts int(11) NOT NULL DEFAULT 0,
            locked_until datetime DEFAULT NULL,
            last_attempt datetime DEFAULT CURRENT_TIMESTAMP,
            user_agent text DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address),
            KEY username (username),
            KEY last_attempt (last_attempt)
        ) $charset_collate;";

        // Security log table with country and path
        $log_table = $wpdb->prefix . 'ms_security_log';
        $sql2 = "CREATE TABLE $log_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            ip_address varchar(45) NOT NULL,
            user_id bigint(20) DEFAULT NULL,
            description text NOT NULL,
            severity enum('low','medium','high','critical') DEFAULT 'medium',
            country varchar(100) DEFAULT NULL,
            path varchar(255) DEFAULT NULL,
            user_agent text DEFAULT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY ip_address (ip_address),
            KEY created_at (created_at),
            KEY severity (severity),
            KEY country (country)
        ) $charset_collate;";

        // Blocked IPs table
        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';
        $sql3 = "CREATE TABLE $blocked_table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            reason varchar(255) NOT NULL,
            blocked_until datetime DEFAULT NULL,
            permanent tinyint(1) DEFAULT 0,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
        dbDelta($sql2);
        dbDelta($sql3);

        // Update existing tables if needed
        $this->ms_update_existing_tables();
    }

    private function ms_update_existing_tables() {
        global $wpdb;

        $log_table = $wpdb->prefix . 'ms_security_log';

        // Check if country column exists
        $country_exists = $wpdb->get_results($wpdb->prepare(
            "SHOW COLUMNS FROM $log_table LIKE %s",
            'country'
        ));

        if (empty($country_exists)) {
            $wpdb->query("ALTER TABLE $log_table ADD COLUMN country varchar(100) DEFAULT NULL");
            $wpdb->query("ALTER TABLE $log_table ADD INDEX country (country)");
        }

        // Check if path column exists
        $path_exists = $wpdb->get_results($wpdb->prepare(
            "SHOW COLUMNS FROM $log_table LIKE %s",
            'path'
        ));

        if (empty($path_exists)) {
            $wpdb->query("ALTER TABLE $log_table ADD COLUMN path varchar(255) DEFAULT NULL");
        }

        // Check if user_agent column exists
        $ua_exists = $wpdb->get_results($wpdb->prepare(
            "SHOW COLUMNS FROM $log_table LIKE %s",
            'user_agent'
        ));

        if (empty($ua_exists)) {
            $wpdb->query("ALTER TABLE $log_table ADD COLUMN user_agent text DEFAULT NULL");
        }
    }

    private function ms_set_default_security_rules() {
        // Add default .htaccess rules if possible
        $this->ms_update_htaccess_rules();
    }

    private function ms_update_htaccess_rules() {
        if (!function_exists('get_home_path')) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
        }

        $htaccess_file = get_home_path() . '.htaccess';

        if (is_writable($htaccess_file)) {
            $rules = "\n# BEGIN Morden Security\n";
            $rules .= "# Disable directory browsing\n";
            $rules .= "Options -Indexes\n";
            $rules .= "# Protect wp-config.php\n";
            $rules .= "<files wp-config.php>\n";
            $rules .= "order allow,deny\n";
            $rules .= "deny from all\n";
            $rules .= "</files>\n";
            $rules .= "# Protect .htaccess\n";
            $rules .= "<files .htaccess>\n";
            $rules .= "order allow,deny\n";
            $rules .= "deny from all\n";
            $rules .= "</files>\n";
            $rules .= "# END Morden Security\n\n";

            $current_content = file_get_contents($htaccess_file);
            if (strpos($current_content, '# BEGIN Morden Security') === false) {
                file_put_contents($htaccess_file, $rules . $current_content);
            }
        }
    }
}

// Initialize the plugin
MS_Morden_Security::get_instance();