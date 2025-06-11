<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Version {

    const VERSION_OPTION_KEY = 'ms_version';
    const UPGRADE_DATA_KEY = 'ms_upgrade_data';

    public function __construct() {
        add_action('plugins_loaded', array($this, 'check_version'), 5);
        add_action('admin_init', array($this, 'maybe_show_upgrade_notice'));
    }

    public function check_version() {
        $stored_version = get_option(self::VERSION_OPTION_KEY, '0.0.0');

        if (version_compare($stored_version, MS_VERSION, '<')) {
            $this->run_upgrade_routine($stored_version);
            update_option(self::VERSION_OPTION_KEY, MS_VERSION);

            update_option(self::UPGRADE_DATA_KEY, array(
                'from_version' => $stored_version,
                'to_version' => MS_VERSION,
                'upgraded_at' => current_time('mysql'),
                'show_notice' => true
            ));
        }
    }

    private function run_upgrade_routine($from_version) {
        if (version_compare($from_version, '1.2.0', '<')) {
            $this->upgrade_to_120();
        }

        if (version_compare($from_version, '1.2.1', '<')) {
            $this->upgrade_to_121();
        }

        if (version_compare($from_version, '1.3.0', '<')) {
            $this->upgrade_to_130();
        }

        $this->log_upgrade($from_version, MS_VERSION);
    }

    private function upgrade_to_120() {
        $current_settings = get_option('ms_settings', array());

        $new_settings = array_merge($current_settings, array(
            'block_php_uploads' => 1,
            'disable_pingbacks' => 1,
            'enable_bot_protection' => 1,
            'block_author_scans' => 1,
            'enable_file_integrity' => 1
        ));

        update_option('ms_settings', $new_settings);
        MS_Database::create_all_tables();
    }

    private function upgrade_to_121() {
        $settings = get_option('ms_settings', array());

        if (isset($settings['enable_bot_protection']) && $settings['enable_bot_protection'] == 1) {
            delete_transient('ms_bot_protection_cache');
        }

        wp_clear_scheduled_hook('ms_file_integrity_scan');

        if (!wp_next_scheduled('ms_integrity_check')) {
            wp_schedule_event(time(), 'daily', 'ms_integrity_check');
        }

        MS_Database::add_missing_columns();
        MS_Database::add_missing_indexes();
    }

    private function upgrade_to_130() {
        $current_settings = get_option('ms_settings', array());

        $new_settings = array_merge($current_settings, array(
            'hide_login_url' => 0,
            'custom_login_url' => 'secure-login'
        ));

        update_option('ms_settings', $new_settings);

        $backup_dir = WP_CONTENT_DIR . '/ms-backups';
        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);

            $htaccess_content = "Order deny,allow\nDeny from all\n";
            file_put_contents($backup_dir . '/.htaccess', $htaccess_content);
        }
    }

    private function log_upgrade($from_version, $to_version) {
        $log_data = array(
            'timestamp' => current_time('mysql'),
            'from_version' => $from_version,
            'to_version' => $to_version,
            'user_id' => get_current_user_id(),
            'ip_address' => $this->get_client_ip()
        );

        $upgrade_logs = get_option('ms_upgrade_logs', array());
        array_unshift($upgrade_logs, $log_data);

        $upgrade_logs = array_slice($upgrade_logs, 0, 10);

        update_option('ms_upgrade_logs', $upgrade_logs);

        if (class_exists('MS_Core')) {
            $core = MS_Core::get_instance();
            $core->ms_log_security_event('plugin_upgraded',
                "Plugin upgraded from {$from_version} to {$to_version}",
                'low',
                get_current_user_id()
            );
        }
    }

    public function maybe_show_upgrade_notice() {
        $upgrade_data = get_option(self::UPGRADE_DATA_KEY);

        if ($upgrade_data && isset($upgrade_data['show_notice']) && $upgrade_data['show_notice']) {
            add_action('admin_notices', array($this, 'show_upgrade_notice'));
        }
    }

    public function show_upgrade_notice() {
        $upgrade_data = get_option(self::UPGRADE_DATA_KEY);

        if (!$upgrade_data) return;

        echo '<div class="notice notice-success is-dismissible">';
        echo '<p><strong>Morden Security</strong> ' . sprintf(__('has been successfully upgraded from version %s to %s', 'morden-security'),
             esc_html($upgrade_data['from_version']),
             esc_html($upgrade_data['to_version'])) . '</p>';
        echo '<p>' . __('New features: Hide Login URL, Database Prefix Changer, and File Permission Checker are now available!', 'morden-security') . '</p>';
        echo '</div>';

        $upgrade_data['show_notice'] = false;
        update_option(self::UPGRADE_DATA_KEY, $upgrade_data);
    }

    private function get_client_ip() {
        $ip_keys = array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR');

        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    }

    public static function get_current_version() {
        return MS_VERSION;
    }

    public static function get_stored_version() {
        return get_option(self::VERSION_OPTION_KEY, '0.0.0');
    }
}

new MS_Version();
