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

require_once MS_PLUGIN_PATH . 'src/Autoloader/Autoloader.php';
MordenSecurity\Autoloader\Autoloader::register();
MordenSecurity\Autoloader\Autoloader::preloadCriticalClasses();

// Initialize Security Core early
if (class_exists('MordenSecurity\Core\SecurityCore')) {
    $securityCore = new MordenSecurity\Core\SecurityCore();
    $securityCore->initialize();
}

use MordenSecurity\Core\SecurityCore;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;
use MordenSecurity\Utils\GitHubUpdater;
use MordenSecurity\Modules\IPManagement\IPBlocker;
use MordenSecurity\Admin\AdminController;
use MordenSecurity\API\RestAPI;
use MordenSecurity\Modules\WAF\RulesetManager;


class MordenSecurityPlugin
{
    private static ?MordenSecurityPlugin $instance = null;
    private bool $initialized = false;
    private ?SecurityCore $securityCore = null;
    private ?AdminController $adminController = null;
    private ?GitHubUpdater $githubUpdater = null;
    private ?RestAPI $restApi = null;

    public static function getInstance(): MordenSecurityPlugin
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
        add_action('wp_login', [$this, 'handleAdminLogin'], 10, 2);
        add_action('admin_notices', [$this, 'showAdminNotices']);
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

        try {
            $this->securityCore = new SecurityCore();
            $this->securityCore->initialize();

            $this->githubUpdater = new GitHubUpdater();
            $this->restApi = new RestAPI();

            if (is_admin()) {
                $this->adminController = new AdminController();
            }

            // WordPressHardening is now autoloaded and initialized via its constructor
            // and admin_init hook, so no direct instantiation here.

            $this->initialized = true;

        } catch (Exception $e) {
            add_action('admin_notices', function() use ($e) {
                echo '<div class="notice notice-error"><p>';
                echo 'Morden Security Error: ' . esc_html($e->getMessage());
                echo '</p></div>';
            });
        }
    }

    public function activate(): void
    {
        if (!file_exists(MS_LOGS_DIR)) {
            wp_mkdir_p(MS_LOGS_DIR);
        }

        if (!file_exists(MS_CACHE_DIR)) {
            wp_mkdir_p(MS_CACHE_DIR);
        }

        $this->autoWhitelistCurrentAdmin();
        $this->setDefaultOptions();

        try {
            $logger = new LoggerSQLite();
            $rulesetManager = new RulesetManager($logger);
            $rulesetManager->syncRulesetsToDatabase();
        } catch (Exception $e) {
            add_option('ms_activation_error', $e->getMessage());
        }
    }

    public function handleAdminLogin(string $userLogin, $user): void
    {
        if (user_can($user, 'administrator')) {
            $ipAddress = IPUtils::getRealClientIP();

            try {
                $logger = new LoggerSQLite();
                $ipBlocker = new IPBlocker($logger);
                $ipBlocker->removeBlock($ipAddress);
            } catch (Exception $e) {
                error_log('MS: Emergency admin unblock failed - ' . $e->getMessage());
            }
        }
    }

    public function showAdminNotices(): void
    {
        if (!current_user_can('administrator')) {
            return;
        }

        $ipAddress = IPUtils::getRealClientIP();

        try {
            $logger = new LoggerSQLite();
            $rule = $logger->getIPRule($ipAddress);

            if ($rule && in_array($rule['rule_type'], ['whitelist', 'temp_whitelist'])) {
                $expiryTime = $rule['blocked_until'] ?
                    date('Y-m-d H:i:s', $rule['blocked_until']) : 'Permanent';

                echo '<div class="notice notice-info">';
                echo '<p><strong>Morden Security:</strong> Your IP (' . esc_html($ipAddress) . ') is whitelisted';

                if ($rule['rule_type'] === 'temp_whitelist') {
                    echo ' until ' . esc_html($expiryTime);
                }

                echo '</p></div>';
            }
        } catch (Exception $e) {
            // Silently handle errors in admin notices
        }
    }

    private function autoWhitelistCurrentAdmin(): void
    {
        if (!current_user_can('administrator')) {
            return;
        }

        $currentUser = wp_get_current_user();
        $ipAddress = IPUtils::getRealClientIP();

        try {
            $logger = new LoggerSQLite();

            $whitelistData = [
                'ip_address' => $ipAddress,
                'rule_type' => 'temp_whitelist',
                'block_duration' => 'temporary',
                'blocked_until' => time() + (24 * 3600),
                'reason' => "Plugin activation by admin: {$currentUser->user_login}",
                'threat_score' => 0,
                'block_source' => 'plugin_activation',
                'created_by' => $currentUser->ID,
                'escalation_count' => 0,
                'notes' => 'Auto-whitelist during plugin activation - 24 hours'
            ];

            $logger->addIPRule($whitelistData);

        } catch (Exception $e) {
            error_log('MS: Failed to whitelist admin during activation - ' . $e->getMessage());
        }
    }

    private function checkSystemRequirements(): bool
    {
        return version_compare(PHP_VERSION, MS_MIN_PHP_VERSION, '>=') &&
               version_compare($GLOBALS['wp_version'], MS_MIN_WP_VERSION, '>=') &&
               extension_loaded('sqlite3');
    }

    private function setDefaultOptions(): void
    {
        $defaults = [
            'ms_security_enabled' => true,
            'ms_firewall_enabled' => true,
            'ms_bot_detection_enabled' => true,
            'ms_logging_enabled' => true
        ];

        foreach ($defaults as $option => $value) {
            if (get_option($option) === false) {
                add_option($option, $value);
            }
        }
    }

    public function showSystemRequirementsError(): void
    {
        echo '<div class="notice notice-error"><p>';
        echo __('Morden Security requires PHP 7.4+, WordPress 5.0+, and SQLite3 extension to function properly.', MS_TEXT_DOMAIN);
        echo '</p></div>';
    }

    public function deactivate(): void
    {
        // Cleanup tasks if needed
    }
}

MordenSecurityPlugin::getInstance();
