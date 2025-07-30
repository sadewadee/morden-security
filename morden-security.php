<?php
/**
 * Plugin Name: Morden Security
 * Plugin URI: https://github.com/sadewadee/morden-security
 * Description: Advanced WordPress security plugin with AI-powered threat detection, automatic IP blocking, and comprehensive protection system.
 * Version: 1.0.0
 * Author: Morden Team
 * Author URI: https://mordenhost.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: morden-security
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.6
 * Requires PHP: 7.4
 * Network: true
 * Update URI: https://github.com/sadewadee/morden-security
 */

if (!defined('ABSPATH')) {
    exit;
}

define('MS_PLUGIN_VERSION', '1.0.0');
define('MS_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('MS_PLUGIN_URL', plugin_dir_url(__FILE__));
define('MS_PLUGIN_FILE', __FILE__);
define('MS_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('MS_UPLOADS_DIR', wp_upload_dir()['basedir'] . '/morden-security/');
define('MS_LOGS_DIR', MS_UPLOADS_DIR . 'logs/');
define('MS_CACHE_DIR', MS_UPLOADS_DIR . 'cache/');
define('MS_TEXT_DOMAIN', 'morden-security');
define('MS_MIN_PHP_VERSION', '7.4');
define('MS_MIN_WP_VERSION', '5.0');
define('MS_NAMESPACE', 'MordenSecurity');
define('MS_GITHUB_REPO', 'sadewadee/morden-security');
define('MS_GITHUB_API_URL', 'https://api.github.com/repos/' . MS_GITHUB_REPO);
define('MS_UPDATE_CHECK_INTERVAL', 12 * HOUR_IN_SECONDS);

// Use Composer's autoloader
if (file_exists(MS_PLUGIN_PATH . 'vendor/autoload.php')) {
    require_once MS_PLUGIN_PATH . 'vendor/autoload.php';
}

use MordenSecurity\Core\SecurityCore;

final class MordenSecurityPlugin
{
    private static ?self $instance = null;
    private SecurityCore $securityCore;
    private bool $initialized = false;

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        $this->registerHooks();
    }

    private function registerHooks(): void
    {
        register_activation_hook(MS_PLUGIN_FILE, [$this, 'activate']);
        register_deactivation_hook(MS_PLUGIN_FILE, [$this, 'deactivate']);

        add_action('plugins_loaded', [$this, 'initialize']);
        add_action('wp_loaded', [$this, 'interceptRequests'], 1);
    }

    public function initialize(): void
    {
        if ($this->initialized) {
            return;
        }

        if (!$this->checkSystemRequirements()) {
            add_action('admin_notices', [$this, 'showSystemRequirementsError']);
            return;
        }

        $this->securityCore = new SecurityCore();
        $this->securityCore->initialize();

        $this->initialized = true;
    }

    public function interceptRequests(): void
    {
        if (!$this->initialized) {
            return;
        }

        $this->securityCore->interceptRequest();
    }

    private function checkSystemRequirements(): bool
    {
        if (version_compare(PHP_VERSION, MS_MIN_PHP_VERSION, '<')) {
            return false;
        }

        if (version_compare($GLOBALS['wp_version'], MS_MIN_WP_VERSION, '<')) {
            return false;
        }

        $requiredExtensions = ['sqlite3', 'openssl', 'json'];
        foreach ($requiredExtensions as $extension) {
            if (!extension_loaded($extension)) {
                return false;
            }
        }

        return true;
    }

    public function activate(): void
    {
        if (!$this->checkSystemRequirements()) {
            wp_die(__('Morden Security requires PHP 7.4+, WordPress 5.0+, and SQLite3 extension.', MS_TEXT_DOMAIN));
        }

        $this->createDirectoryStructure();
        $this->createSecurityFiles();
        $this->initializeDatabase();
        $this->setDefaultOptions();
        $this->scheduleMaintenanceTasks();

        flush_rewrite_rules();
    }

    public function deactivate(): void
    {
        wp_clear_scheduled_hook('ms_cleanup_temp_blocks');
        wp_clear_scheduled_hook('ms_rotate_logs');
        wp_clear_scheduled_hook('ms_update_geo_data');
        wp_clear_scheduled_hook('ms_optimize_database');
        wp_clear_scheduled_hook('ms_check_updates');

        flush_rewrite_rules();
    }

    private function createDirectoryStructure(): void
    {
        $directories = [
            MS_UPLOADS_DIR,
            MS_LOGS_DIR,
            MS_LOGS_DIR . 'archived/',
            MS_CACHE_DIR,
            MS_UPLOADS_DIR . 'backups/',
            MS_UPLOADS_DIR . 'temp/'
        ];

        foreach ($directories as $dir) {
            if (!wp_mkdir_p($dir)) {
                wp_die(sprintf(__('Failed to create directory: %s', MS_TEXT_DOMAIN), $dir));
            }
        }
    }

    private function createSecurityFiles(): void
    {
        $htaccessContent = "<Files \"*\">\n    Order allow,deny\n    Deny from all\n</Files>";
        file_put_contents(MS_UPLOADS_DIR . '.htaccess', $htaccessContent);

        $indexContent = '<?php // Silence is golden';
        file_put_contents(MS_UPLOADS_DIR . 'index.php', $indexContent);
    }

    private function initializeDatabase(): void
    {
        require_once MS_PLUGIN_PATH . 'src/Core/LoggerSQLite.php';
        $logger = new MordenSecurity\Core\LoggerSQLite();
        $logger->createTables();
    }

    private function setDefaultOptions(): void
    {
        $defaultOptions = [
            'ms_version' => MS_PLUGIN_VERSION,
            'ms_db_version' => '1.0',
            'ms_installation_date' => time(),
            'ms_firewall_enabled' => true,
            'ms_auto_blocking_enabled' => true,
            'ms_bot_detection_enabled' => true,
            'ms_logging_enabled' => true,
            'ms_github_updates_enabled' => true
        ];

        foreach ($defaultOptions as $option => $value) {
            add_option($option, $value);
        }
    }

    private function scheduleMaintenanceTasks(): void
    {
        if (!wp_next_scheduled('ms_cleanup_temp_blocks')) {
            wp_schedule_event(time(), 'hourly', 'ms_cleanup_temp_blocks');
        }

        if (!wp_next_scheduled('ms_rotate_logs')) {
            wp_schedule_event(time(), 'daily', 'ms_rotate_logs');
        }

        if (!wp_next_scheduled('ms_optimize_database')) {
            wp_schedule_event(time(), 'weekly', 'ms_optimize_database');
        }
    }

    public function showSystemRequirementsError(): void
    {
        echo '<div class="notice notice-error"><p>';
        echo __('Morden Security requires PHP 7.4+, WordPress 5.0+, and SQLite3 extension to function properly.', MS_TEXT_DOMAIN);
        echo '</p></div>';
    }
}

MordenSecurityPlugin::getInstance();
