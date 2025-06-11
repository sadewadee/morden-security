<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Version {

    private static $instance = null;
    private $current_version;
    private $changelog;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->current_version = '1.5.0';
        $this->init_changelog();
    }

    private function init_changelog() {
        $this->changelog = array(
            '1.5.0' => array(
                'release_date' => '2025-01-12',
                'type' => 'major',
                'changes' => array(
                    'added' => array(
                        'Advanced Firewall Protection (equivalent to modern generation firewall)',
                        'Comprehensive IP Whitelist Management with auto-detection',
                        'File Permissions Checker with deep scanning capabilities',
                        'WordPress Integrity Checker with malware detection',
                        'Rate Limiter for API and login protection',
                        'Enhanced Admin Interface with modern eye-catchy design',
                        'Namespace support (MordenSecurity) for future development',
                        'Comprehensive error handling and logging system',
                        'Auto-admin IP whitelisting on login',
                        'File upload security scanning with content analysis',
                        'POST data analysis for advanced threat detection',
                        'Enhanced bot protection with extensive bad bot database',
                        'Geolocation support with multiple API fallbacks',
                        'Custom block pages with branded design'
                    ),
                    'improved' => array(
                        'Firewall engine completely rewritten for better performance',
                        'Admin dashboard with real-time statistics and monitoring',
                        'Security logs page with advanced filtering and export',
                        'Blocked IPs management with country detection',
                        'Database operations with proper error handling',
                        'AJAX calls with timeout protection and retry logic',
                        'Form validation and input sanitization',
                        'WordPress compatibility and standards compliance',
                        'Mobile responsive design for all admin pages',
                        'Performance optimization with caching mechanisms'
                    ),
                    'fixed' => array(
                        'Class loading issues and missing file dependencies',
                        'Endless loading states in admin pages',
                        'File permission checker not working properly',
                        'Database table creation errors on activation',
                        'AJAX nonce verification failures',
                        'CSS styling inconsistencies across admin pages',
                        'Memory leaks in firewall processing',
                        'Timezone issues in logging system',
                        'Plugin activation errors on various hosting environments',
                        'Compatibility issues with other security plugins'
                    ),
                    'security' => array(
                        'Enhanced SQL injection protection patterns',
                        'Advanced XSS prevention with modern evasion detection',
                        'Directory traversal protection improvements',
                        'File inclusion vulnerability patches',
                        'Code injection prevention enhancements',
                        'Protocol manipulation blocking',
                        'Header injection protection',
                        'Null byte injection prevention',
                        'Advanced encoding detection and blocking',
                        'Zero-day exploit protection patterns'
                    )
                ),
                'breaking_changes' => array(),
                'notes' => 'Major release with comprehensive security enhancements and modern admin interface. All existing functionality preserved with backward compatibility.'
            ),
            '1.4.0' => array(
                'release_date' => '2024-12-15',
                'type' => 'minor',
                'changes' => array(
                    'added' => array(
                        'Enhanced login protection with IP tracking',
                        'Improved security headers implementation',
                        'Better WordPress core file protection'
                    ),
                    'improved' => array(
                        'Performance optimizations',
                        'Better error handling',
                        'Updated admin interface'
                    ),
                    'fixed' => array(
                        'Minor bug fixes',
                        'Compatibility improvements'
                    )
                )
            ),
            '1.3.0' => array(
                'release_date' => '2024-11-20',
                'type' => 'minor',
                'changes' => array(
                    'added' => array(
                        'Basic firewall protection',
                        'Login attempt limiting',
                        'Security logging system'
                    )
                )
            ),
            '1.2.0' => array(
                'release_date' => '2024-10-15',
                'type' => 'minor',
                'changes' => array(
                    'added' => array(
                        'Security headers',
                        'File editor protection',
                        'XML-RPC blocking'
                    )
                )
            ),
            '1.1.0' => array(
                'release_date' => '2024-09-10',
                'type' => 'minor',
                'changes' => array(
                    'added' => array(
                        'Basic security features',
                        'Admin interface',
                        'Settings management'
                    )
                )
            ),
            '1.0.0' => array(
                'release_date' => '2024-08-01',
                'type' => 'major',
                'changes' => array(
                    'added' => array(
                        'Initial release',
                        'Core security framework',
                        'Plugin foundation'
                    )
                )
            )
        );
    }

    public function get_current_version() {
        return $this->current_version;
    }

    public function get_changelog($version = null) {
        if ($version) {
            return $this->changelog[$version] ?? null;
        }
        return $this->changelog;
    }

    public function get_latest_changes() {
        return $this->changelog[$this->current_version] ?? array();
    }

    public function is_version_newer($version) {
        return version_compare($version, $this->current_version, '>');
    }

    public function get_version_info() {
        return array(
            'current_version' => $this->current_version,
            'release_date' => $this->changelog[$this->current_version]['release_date'] ?? 'Unknown',
            'type' => $this->changelog[$this->current_version]['type'] ?? 'unknown',
            'wordpress_tested' => '6.7.2',
            'php_required' => '7.4',
            'php_tested' => '8.3',
            'mysql_required' => '5.7',
            'features_count' => $this->count_features(),
            'security_rules' => $this->count_security_rules()
        );
    }

    private function count_features() {
        $latest = $this->get_latest_changes();
        $total = 0;

        if (isset($latest['changes']['added'])) {
            $total += count($latest['changes']['added']);
        }

        return $total;
    }

    private function count_security_rules() {
        $latest = $this->get_latest_changes();

        if (isset($latest['changes']['security'])) {
            return count($latest['changes']['security']);
        }

        return 0;
    }

    public function get_upgrade_notice() {
        $latest = $this->get_latest_changes();

        if (empty($latest)) {
            return '';
        }

        $notice = "Morden Security {$this->current_version} includes:\n\n";

        if (!empty($latest['changes']['added'])) {
            $notice .= "NEW FEATURES:\n";
            foreach (array_slice($latest['changes']['added'], 0, 5) as $feature) {
                $notice .= "• {$feature}\n";
            }
            $notice .= "\n";
        }

        if (!empty($latest['changes']['security'])) {
            $notice .= "SECURITY ENHANCEMENTS:\n";
            foreach (array_slice($latest['changes']['security'], 0, 3) as $security) {
                $notice .= "• {$security}\n";
            }
            $notice .= "\n";
        }

        if (!empty($latest['breaking_changes'])) {
            $notice .= "⚠️ BREAKING CHANGES:\n";
            foreach ($latest['breaking_changes'] as $change) {
                $notice .= "• {$change}\n";
            }
            $notice .= "\n";
        }

        if (!empty($latest['notes'])) {
            $notice .= "NOTE: {$latest['notes']}\n";
        }

        return $notice;
    }

    public function get_migration_info($from_version) {
        $migrations = array();

        // Check if migration is needed
        if (version_compare($from_version, $this->current_version, '>=')) {
            return array('required' => false);
        }

        // Version-specific migrations
        if (version_compare($from_version, '1.5.0', '<')) {
            $migrations[] = array(
                'version' => '1.5.0',
                'description' => 'Database schema updates for new security features',
                'actions' => array(
                    'Create new database tables for integrity checking',
                    'Update existing tables with new columns',
                    'Migrate old settings to new format',
                    'Initialize new security rules'
                ),
                'backup_recommended' => true
            );
        }

        if (version_compare($from_version, '1.4.0', '<')) {
            $migrations[] = array(
                'version' => '1.4.0',
                'description' => 'Security enhancements and new features',
                'actions' => array(
                    'Update firewall rules',
                    'Migrate login protection settings'
                ),
                'backup_recommended' => false
            );
        }

        return array(
            'required' => !empty($migrations),
            'migrations' => $migrations,
            'total_steps' => array_sum(array_map(function($m) {
                return count($m['actions']);
            }, $migrations))
        );
    }

    public function check_compatibility() {
        $issues = array();

        // PHP version check
        if (version_compare(PHP_VERSION, '7.4', '<')) {
            $issues[] = array(
                'type' => 'error',
                'message' => 'PHP 7.4 or higher is required. Current version: ' . PHP_VERSION
            );
        }

        // WordPress version check
        global $wp_version;
        if (version_compare($wp_version, '6.1', '<')) {
            $issues[] = array(
                'type' => 'warning',
                'message' => 'WordPress 6.1 or higher is recommended. Current version: ' . $wp_version
            );
        }

        // MySQL version check
        global $wpdb;
        $mysql_version = $wpdb->get_var('SELECT VERSION()');
        if (version_compare($mysql_version, '5.7', '<')) {
            $issues[] = array(
                'type' => 'warning',
                'message' => 'MySQL 5.7 or higher is recommended. Current version: ' . $mysql_version
            );
        }

        // Memory limit check
        $memory_limit = ini_get('memory_limit');
        $memory_bytes = $this->convert_to_bytes($memory_limit);
        if ($memory_bytes < 128 * 1024 * 1024) { // 128MB
            $issues[] = array(
                'type' => 'warning',
                'message' => 'Memory limit of 128MB or higher is recommended. Current: ' . $memory_limit
            );
        }

        // Required extensions
        $required_extensions = array('curl', 'json', 'mbstring', 'openssl');
        foreach ($required_extensions as $ext) {
            if (!extension_loaded($ext)) {
                $issues[] = array(
                    'type' => 'error',
                    'message' => "Required PHP extension '{$ext}' is not loaded"
                );
            }
        }

        return array(
            'compatible' => empty(array_filter($issues, function($i) { return $i['type'] === 'error'; })),
            'issues' => $issues
        );
    }

    private function convert_to_bytes($value) {
        $value = trim($value);
        $last = strtolower($value[strlen($value)-1]);
        $value = (int) $value;

        switch($last) {
            case 'g': $value *= 1024;
            case 'm': $value *= 1024;
            case 'k': $value *= 1024;
        }

        return $value;
    }

    public function get_system_info() {
        global $wp_version, $wpdb;

        return array(
            'plugin_version' => $this->current_version,
            'wordpress_version' => $wp_version,
            'php_version' => PHP_VERSION,
            'mysql_version' => $wpdb->get_var('SELECT VERSION()'),
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'upload_max_filesize' => ini_get('upload_max_filesize'),
            'post_max_size' => ini_get('post_max_size'),
            'loaded_extensions' => get_loaded_extensions(),
            'active_plugins' => get_option('active_plugins', array()),
            'multisite' => is_multisite(),
            'ssl_enabled' => is_ssl(),
            'debug_mode' => defined('WP_DEBUG') && WP_DEBUG
        );
    }
}
