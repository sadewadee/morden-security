<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Admin {

    private static $instance = null;
    private $core;
    private $template_path;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->core = MS_Core::get_instance();
        $this->template_path = MS_PLUGIN_PATH . 'admin/';
        $this->init_admin();
    }

    private function init_admin() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('admin_notices', array($this, 'show_admin_notices'));

        $this->init_ajax_handlers();
    }

    private function init_ajax_handlers() {
        $ajax_actions = array(
            'ms_get_security_stats',
            'ms_get_security_logs',
            'ms_export_security_logs',
            'ms_unblock_ip',
            'ms_block_ip_from_logs',
            'ms_block_ip_manually',
            'ms_run_integrity_check',
            'ms_get_detailed_report',
            'ms_change_db_prefix',
            'ms_check_permissions',
            'ms_fix_permissions',
            'ms_get_firewall_stats',
            'ms_get_blocked_ips',
            'ms_get_whitelist_info'
        );

        foreach ($ajax_actions as $action) {
            add_action('wp_ajax_' . $action, array($this, $action . '_ajax'));
        }
    }

    public function add_admin_menu() {
        $icon_svg = 'data:image/svg+xml;base64,' . base64_encode(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 1L3 5V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V5L12 1M12 7C13.4 7 14.8 8.6 14.8 10V11.5C15.4 11.5 16 12.4 16 13V16C16 17.4 15.4 18 14.8 18H9.2C8.6 18 8 17.4 8 16V13C8 12.4 8.6 11.5 9.2 11.5V10C9.2 8.6 10.6 7 12 7M12 8.2C11.2 8.2 10.5 8.7 10.5 10V11.5H13.5V10C13.5 8.7 12.8 8.2 12 8.2Z"/>
            </svg>'
        );

        add_menu_page(
            __('Morden Security', 'morden-security'),
            __('Morden Security', 'morden-security'),
            'manage_options',
            'morden-security',
            array($this, 'render_dashboard_page'),
            $icon_svg,
            30
        );

        add_submenu_page(
            'morden-security',
            __('Security Dashboard', 'morden-security'),
            __('Dashboard', 'morden-security'),
            'manage_options',
            'morden-security',
            array($this, 'render_dashboard_page')
        );

        add_submenu_page(
            'morden-security',
            __('General Settings', 'morden-security'),
            __('Settings', 'morden-security'),
            'manage_options',
            'ms-settings',
            array($this, 'render_settings_page')
        );

        add_submenu_page(
            'morden-security',
            __('Security Logs', 'morden-security'),
            __('Security Logs', 'morden-security'),
            'manage_options',
            'ms-security-logs',
            array($this, 'render_security_logs_page')
        );

        add_submenu_page(
            'morden-security',
            __('Blocked IPs', 'morden-security'),
            __('Blocked IPs', 'morden-security'),
            'manage_options',
            'ms-blocked-ips',
            array($this, 'render_blocked_ips_page')
        );

        add_submenu_page(
            'morden-security',
            __('IP Whitelist', 'morden-security'),
            __('IP Whitelist', 'morden-security'),
            'manage_options',
            'ms-ip-whitelist',
            array($this, 'render_ip_whitelist_page')
        );
    }

    public function register_settings() {
        register_setting(
            'ms_settings_group',
            'ms_settings',
            array($this, 'sanitize_settings')
        );

        add_settings_section(
            'ms_general_section',
            __('General Settings', 'morden-security'),
            array($this, 'general_section_callback'),
            'ms_settings'
        );
    }

    public function general_section_callback() {
        echo '<p>' . __('Configure your security settings below.', 'morden-security') . '</p>';
    }

    public function enqueue_admin_scripts($hook) {
        $allowed_pages = array(
            'toplevel_page_morden-security',
            'morden-security_page_ms-settings',
            'morden-security_page_ms-security-logs',
            'morden-security_page_ms-blocked-ips',
            'morden-security_page_ms-ip-whitelist'
        );

        if (!in_array($hook, $allowed_pages)) {
            return;
        }

        wp_enqueue_style(
            'ms-admin-style',
            MS_PLUGIN_URL . 'admin/css/admin-style.css',
            array(),
            MS_VERSION
        );

        wp_enqueue_script(
            'ms-admin-script',
            MS_PLUGIN_URL . 'admin/js/admin-script.js',
            array('jquery'),
            MS_VERSION,
            true
        );

        wp_localize_script('ms-admin-script', 'ms_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ms_admin_nonce'),
            'confirm_block_ip' => __('Are you sure you want to block this IP address?', 'morden-security'),
            'confirm_unblock_ip' => __('Are you sure you want to unblock this IP address?', 'morden-security'),
            'block_ip' => __('Block IP', 'morden-security'),
            'unblock' => __('Unblock', 'morden-security'),
            'blocking_ip' => __('Blocking...', 'morden-security'),
            'unblocking_ip' => __('Unblocking...', 'morden-security'),
            'scanning' => __('Scanning...', 'morden-security'),
            'fixing' => __('Fixing...', 'morden-security')
        ));
    }

    public function show_admin_notices() {
        $screen = get_current_screen();
        if (!$screen || strpos($screen->id, 'morden-security') === false) {
            return;
        }

        if (isset($_GET['settings-updated']) && $_GET['settings-updated']) {
            echo '<div class="notice notice-success is-dismissible">';
            echo '<p>' . __('Settings saved successfully!', 'morden-security') . '</p>';
            echo '</div>';
        }

        $this->check_security_warnings();
    }


    private function check_security_warnings() {
        global $wpdb;

        if ($wpdb->prefix === 'wp_') {
            echo '<div class="notice notice-warning">';
            echo '<p><strong>' . __('Security Warning:', 'morden-security') . '</strong> ';
            echo __('You are using the default database prefix "wp_" which is insecure.', 'morden-security');
            echo ' <a href="' . admin_url('admin.php?page=ms-settings#security') . '">' . __('Change it now', 'morden-security') . '</a></p>';
            echo '</div>';
        }

        if (!is_ssl() && $this->core->ms_get_option('force_ssl', 1)) {
            echo '<div class="notice notice-warning">';
            echo '<p><strong>' . __('SSL Warning:', 'morden-security') . '</strong> ';
            echo __('Your site is not using HTTPS. Consider enabling SSL for better security.', 'morden-security') . '</p>';
            echo '</div>';
        }
    }

    public function render_dashboard_page() {
        $this->render_template('dashboard-page');
    }

    public function render_settings_page() {
        $this->render_template('admin-page');
    }

    public function render_security_logs_page() {
        $this->render_template('security-logs-page');
    }

    public function render_blocked_ips_page() {
        $this->render_template('blocked-ips-page');
    }

    public function render_ip_whitelist_page() {
        $this->render_template('ip-whitelist-page');
    }

    private function render_template($template_name, $args = array()) {
        $template_path = $this->template_path . $template_name . '.php';

        if (!is_readable($template_path)) {
            echo '<div class="notice notice-error"><p>' .
                 sprintf(__('Template file not found: %s', 'morden-security'), $template_name) .
                 '</p></div>';
            return;
        }

        if (!empty($args)) {
            extract($args, EXTR_SKIP);
        }

        include $template_path;
    }

    public function ms_get_security_stats_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        global $wpdb;

        $stats = array();

        $login_table = $wpdb->prefix . 'ms_login_attempts';
        $stats['login_attempts'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $login_table WHERE last_attempt > %s",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));

        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';
        $stats['blocked_ips'] = $wpdb->get_var("SELECT COUNT(*) FROM $blocked_table");

        $log_table = $wpdb->prefix . 'ms_security_log';
        $stats['security_events'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table WHERE created_at > %s",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));

        $stats['firewall_blocks'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE event_type = 'firewall_block' AND created_at > %s",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));

        wp_send_json_success($stats);
    }

    public function ms_get_security_logs_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $severity = sanitize_text_field($_POST['severity'] ?? '');
        $days = absint($_POST['days'] ?? 7);
        $limit = absint($_POST['limit'] ?? 100);
        $offset = absint($_POST['offset'] ?? 0);

        global $wpdb;

        $log_table = $wpdb->prefix . 'ms_security_log';
        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';

        $where_conditions = array("l.created_at > DATE_SUB(NOW(), INTERVAL %d DAY)");
        $params = array($days);

        if (!empty($severity)) {
            $where_conditions[] = "l.severity = %s";
            $params[] = $severity;
        }

        $where_clause = implode(' AND ', $where_conditions);

        $query = "SELECT l.*,
                         CASE WHEN b.ip_address IS NOT NULL THEN 1 ELSE 0 END as is_blocked
                  FROM $log_table l
                  LEFT JOIN $blocked_table b ON l.ip_address = b.ip_address
                  WHERE $where_clause
                  ORDER BY l.created_at DESC
                  LIMIT %d OFFSET %d";

        $params[] = $limit;
        $params[] = $offset;

        $logs = $wpdb->get_results($wpdb->prepare($query, $params));

        $total_query = "SELECT COUNT(*) FROM $log_table l WHERE $where_clause";
        array_pop($params); // Remove offset
        array_pop($params); // Remove limit
        $total = $wpdb->get_var($wpdb->prepare($total_query, $params));

        wp_send_json_success(array(
            'logs' => $logs,
            'total' => $total
        ));
    }

    public function ms_block_ip_from_logs_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $ip = sanitize_text_field($_POST['ip'] ?? '');
        $reason = sanitize_text_field($_POST['reason'] ?? '');

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(__('Invalid IP address.', 'morden-security'));
            return;
        }

        if (empty($reason)) {
            $reason = 'Blocked from security logs';
        }

        $result = $this->core->ms_block_ip($ip, $reason, 3600);

        if ($result) {
            wp_send_json_success(__('IP address blocked successfully.', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to block IP address.', 'morden-security'));
        }
    }

    public function ms_block_ip_manually_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $ip = sanitize_text_field($_POST['ip_address'] ?? '');
        $reason = sanitize_text_field($_POST['reason'] ?? '');
        $block_type = sanitize_text_field($_POST['block_type'] ?? 'temporary');

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(__('Invalid IP address.', 'morden-security'));
            return;
        }

        if (empty($reason)) {
            wp_send_json_error(__('Reason is required.', 'morden-security'));
            return;
        }

        $duration = ($block_type === 'permanent') ? 0 : 3600;
        $permanent = ($block_type === 'permanent');

        $result = $this->core->ms_block_ip($ip, $reason, $duration, $permanent);

        if ($result) {
            wp_send_json_success(__('IP address blocked successfully.', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to block IP address.', 'morden-security'));
        }
    }

    public function ms_unblock_ip_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $ip = sanitize_text_field($_POST['ip'] ?? '');

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(__('Invalid IP address.', 'morden-security'));
            return;
        }

        global $wpdb;

        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';
        $result = $wpdb->delete($blocked_table, array('ip_address' => $ip), array('%s'));

        if ($result !== false) {
            $this->core->ms_log_security_event('ip_unblocked',
                "IP unblocked manually: {$ip}",
                'low',
                get_current_user_id()
            );

            wp_send_json_success(__('IP address unblocked successfully.', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to unblock IP address.', 'morden-security'));
        }
    }

    public function ms_get_blocked_ips_ajax() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'ms_admin_nonce')) {
            wp_send_json_error(__('Security check failed.', 'morden-security'));
            return;
        }

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        try {
            global $wpdb;

            $blocked_table = $wpdb->prefix . 'ms_blocked_ips';

            // Check if table exists
            if ($wpdb->get_var("SHOW TABLES LIKE '$blocked_table'") != $blocked_table) {
                wp_send_json_error(__('Database table not found.', 'morden-security'));
                return;
            }

            $blocked_ips = $wpdb->get_results(
                "SELECT * FROM $blocked_table
                ORDER BY created_at DESC
                LIMIT 1000",
                ARRAY_A
            );

            if ($wpdb->last_error) {
                error_log('MS Blocked IPs Query Error: ' . $wpdb->last_error);
                wp_send_json_error(__('Database query failed.', 'morden-security'));
                return;
            }

            // Process results using existing core method
            $processed_ips = array();
            foreach ($blocked_ips as $ip) {
                $processed_ips[] = array(
                    'ip_address' => $ip['ip_address'],
                    'reason' => $ip['reason'],
                    'blocked_until' => $ip['blocked_until'],
                    'permanent' => $ip['permanent'],
                    'created_at' => $ip['created_at'],
                    'country' => $this->core->ms_get_country_from_ip($ip['ip_address']) // FIXED: Gunakan method yang sudah ada
                );
            }

            wp_send_json_success($processed_ips);

        } catch (Exception $e) {
            error_log('MS Blocked IPs Error: ' . $e->getMessage());
            wp_send_json_error(__('An error occurred while loading blocked IPs.', 'morden-security'));
        }
    }

    public function ms_change_db_prefix_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $new_prefix = sanitize_text_field($_POST['new_prefix'] ?? '');

        if (empty($new_prefix) || !preg_match('/^[a-zA-Z0-9_]+$/', $new_prefix)) {
            wp_send_json_error(__('Invalid prefix. Use only letters, numbers, and underscores.', 'morden-security'));
            return;
        }

        if (!str_ends_with($new_prefix, '_')) {
            $new_prefix .= '_';
        }

        try {
            $result = $this->change_database_prefix($new_prefix);
            if ($result) {
                wp_send_json_success(__('Database prefix changed successfully! Please log in again.', 'morden-security'));
            } else {
                wp_send_json_error(__('Failed to change database prefix.', 'morden-security'));
            }
        } catch (Exception $e) {
            wp_send_json_error('Error: ' . $e->getMessage());
        }
    }

    private function change_database_prefix($new_prefix) {
        global $wpdb;

        $old_prefix = $wpdb->prefix;

        $tables = $wpdb->get_results("SHOW TABLES LIKE '{$old_prefix}%'", ARRAY_N);

        if (empty($tables)) {
            throw new Exception('No tables found with current prefix.');
        }

        $backup_dir = WP_CONTENT_DIR . '/ms-backups';
        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);
        }

        $backup_file = $backup_dir . '/db-backup-' . date('Y-m-d-H-i-s') . '.sql';
        MS_Database::create_database_backup($backup_file);

        foreach ($tables as $table) {
            $old_table = $table[0];
            $new_table = str_replace($old_prefix, $new_prefix, $old_table);

            $result = $wpdb->query("RENAME TABLE `{$old_table}` TO `{$new_table}`");
            if ($result === false) {
                throw new Exception("Failed to rename table {$old_table}");
            }
        }

        $this->update_wp_config_prefix($new_prefix);

        if (is_multisite()) {
            $wpdb->query($wpdb->prepare(
                "UPDATE {$new_prefix}options SET option_name = %s WHERE option_name = %s",
                $new_prefix . 'user_roles',
                $old_prefix . 'user_roles'
            ));
        }

        $this->core->ms_log_security_event('db_prefix_changed',
            "Database prefix changed from {$old_prefix} to {$new_prefix}",
            'high',
            get_current_user_id()
        );

        return true;
    }

    private function update_wp_config_prefix($new_prefix) {
        $wp_config_path = ABSPATH . 'wp-config.php';

        if (!file_exists($wp_config_path) || !is_writable($wp_config_path)) {
            throw new Exception('wp-config.php is not writable.');
        }

        $content = file_get_contents($wp_config_path);
        $content = preg_replace(
            '/\$table_prefix\s*=\s*[\'"][^\'\"]*[\'"];/',
            "\$table_prefix = '{$new_prefix}';",
            $content
        );

        if (file_put_contents($wp_config_path, $content) === false) {
            throw new Exception('Failed to update wp-config.php');
        }
    }

    public function ms_check_permissions_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $scan_type = sanitize_text_field($_POST['scan_type'] ?? 'basic');
        $permissions_checker = MS_Permissions::get_instance();

        try {
            if ($scan_type === 'deep') {
                $results = $this->perform_deep_scan($permissions_checker);
            } else {
                $results = $permissions_checker->scan_permissions();
            }

            $this->core->ms_log_security_event('permissions_scanned',
                "Permission scan completed: {$results['total_checked']} items checked, {$results['secure_count']} secure",
                'low'
            );

            wp_send_json_success($results);

        } catch (Exception $e) {
            wp_send_json_error('Scan failed: ' . $e->getMessage());
        }
    }

    private function perform_deep_scan($permissions_checker) {
        $basic_results = $permissions_checker->scan_permissions();

        $deep_scan_dirs = array(
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/uploads'
        );

        $deep_issues = array();
        foreach ($deep_scan_dirs as $dir) {
            if (is_dir($dir)) {
                $dir_issues = $permissions_checker->deep_scan_directory($dir, 2);
                $deep_issues = array_merge($deep_issues, $dir_issues);
            }
        }

        $basic_results['deep_scan_issues'] = $deep_issues;
        $basic_results['total_deep_issues'] = count($deep_issues);

        return $basic_results;
    }

    public function ms_fix_permissions_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $fix_type = sanitize_text_field($_POST['fix_type'] ?? 'selected');
        $selected_paths = $_POST['selected_paths'] ?? array();

        $permissions_checker = MS_Permissions::get_instance();

        try {
            if ($fix_type === 'all') {
                $result = $permissions_checker->fix_permissions();
            } else {
                $paths_to_fix = array_map('sanitize_text_field', $selected_paths);
                $full_paths = array_map(function($path) {
                    return ABSPATH . ltrim($path, '/');
                }, $paths_to_fix);

                $result = $permissions_checker->fix_permissions($full_paths);
            }

            $this->core->ms_log_security_event('permissions_fixed',
                "Fixed {$result['fixed_count']} file/folder permissions",
                'medium'
            );

            $message = sprintf(__('Successfully fixed %d file/folder permissions.', 'morden-security'), $result['fixed_count']);

            if (!empty($result['failed_fixes'])) {
                $message .= ' ' . sprintf(__('%d items could not be fixed.', 'morden-security'), count($result['failed_fixes']));
            }

            // Add diagnosis if no permissions were fixed
            if ($result['fixed_count'] === 0 && !empty($result['failed_fixes'])) {
                $diagnosis = $permissions_checker->diagnose_permission_issues();
                $result['diagnosis'] = $diagnosis;

                // Provide specific error guidance
                if (!$diagnosis['chmod_test']) {
                    $message .= ' ' . __('Server restrictions prevent permission changes. Contact your hosting provider.', 'morden-security');
                } elseif ($diagnosis['file_owner'] !== $diagnosis['process_user']) {
                    $message .= ' ' . sprintf(__('File ownership issue detected. Files owned by %s, process running as %s.', 'morden-security'),
                        $diagnosis['file_owner'], $diagnosis['process_user']);
                }
            }

            wp_send_json_success(array(
                'message' => $message,
                'fixed_count' => $result['fixed_count'],
                'failed_fixes' => $result['failed_fixes'],
                'server_info' => $result['server_info'] ?? null,
                'diagnosis' => $result['diagnosis'] ?? null
            ));

        } catch (Exception $e) {
            wp_send_json_error('Fix failed: ' . $e->getMessage());
        }
    }

    public function ms_diagnose_permissions_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $permissions_checker = MS_Permissions::get_instance();
        $diagnosis = $permissions_checker->diagnose_permission_issues();

        wp_send_json_success($diagnosis);
    }

    public function ms_run_integrity_check_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        try {
            // Check if class exists, if not include it
            if (!class_exists('MS_Integrity_Checker')) {
                $integrity_file = MS_PLUGIN_PATH . 'includes/class-ms-integrity-checker.php';
                if (file_exists($integrity_file)) {
                    require_once $integrity_file;
                } else {
                    wp_send_json_error(__('Integrity checker not available.', 'morden-security'));
                    return;
                }
            }

            $integrity_checker = new MS_Integrity_Checker();
            $results = $integrity_checker->check_wordpress_integrity();

            update_option('ms_integrity_check_results', $results);

            $this->core->ms_log_security_event('integrity_check_completed',
                "WordPress integrity check completed: " . $results['status'],
                ($results['status'] === 'clean') ? 'low' : 'high'
            );

            wp_send_json_success(array(
                'message' => __('Integrity check completed successfully.', 'morden-security'),
                'results' => $results
            ));

        } catch (Exception $e) {
            wp_send_json_error('Integrity check failed: ' . $e->getMessage());
        }
    }

    public function ms_get_detailed_report_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        try {
            if (!class_exists('MS_Integrity_Checker')) {
                $integrity_file = MS_PLUGIN_PATH . 'includes/class-ms-integrity-checker.php';
                if (file_exists($integrity_file)) {
                    require_once $integrity_file;
                } else {
                    wp_send_json_error(__('Integrity checker not available.', 'morden-security'));
                    return;
                }
            }

            $integrity_checker = new MS_Integrity_Checker();
            $report = $integrity_checker->get_detailed_report();

            wp_send_json_success($report);

        } catch (Exception $e) {
            wp_send_json_error('Failed to generate report: ' . $e->getMessage());
        }
    }

    public function ms_get_firewall_stats_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $firewall = MS_Firewall::get_instance();
        $stats = $firewall->get_firewall_stats();

        wp_send_json_success($stats);
    }

    public function sanitize_settings($input) {
        $sanitized = array();

        $boolean_fields = array(
            'disable_file_editor', 'force_ssl', 'disable_xmlrpc', 'limit_login_attempts',
            'enable_security_headers', 'hide_wp_version', 'remove_wp_credit',
            'hide_wp_logo', 'hide_admin_bar', 'turnstile_enabled', 'enable_2fa',
            'scan_uploads', 'enable_geolocation', 'block_php_uploads', 'disable_pingbacks',
            'enable_bot_protection', 'block_author_scans', 'enable_file_integrity',
            'hide_login_url', 'enable_firewall', 'firewall_auto_block_ip', 'firewall_custom_block_page'
        );

        foreach ($boolean_fields as $field) {
            $sanitized[$field] = isset($input[$field]) ? 1 : 0;
        }

        $sanitized['max_login_attempts'] = min(max(absint($input['max_login_attempts'] ?? 5), 1), 20);
        $sanitized['lockout_duration'] = min(max(absint($input['lockout_duration'] ?? 1800), 300), 86400);
        $sanitized['max_logs'] = min(max(absint($input['max_logs'] ?? 1000), 100), 10000);
        $sanitized['max_days_retention'] = min(max(absint($input['max_days_retention'] ?? 30), 1), 365);

        $sanitized['turnstile_site_key'] = sanitize_text_field($input['turnstile_site_key'] ?? '');
        $sanitized['turnstile_secret_key'] = sanitize_text_field($input['turnstile_secret_key'] ?? '');

        $sanitized['custom_safe_folders'] = sanitize_textarea_field($input['custom_safe_folders'] ?? '');
        $sanitized['scan_sensitivity'] = in_array($input['scan_sensitivity'] ?? 'medium', array('low', 'medium', 'high'))
            ? $input['scan_sensitivity'] : 'medium';
        $sanitized['max_scan_file_size'] = min(max(absint($input['max_scan_file_size'] ?? 10), 1), 100);

        $custom_login = sanitize_text_field($input['custom_login_url'] ?? 'secure-login');
        $custom_login = preg_replace('/[^a-zA-Z0-9\-_]/', '', $custom_login);
        $sanitized['custom_login_url'] = !empty($custom_login) ? $custom_login : 'secure-login';

        $sanitized['firewall_block_message'] = sanitize_textarea_field($input['firewall_block_message'] ?? 'Access Denied - Your request has been blocked by our security system.');

        $sanitized['admin_whitelist_ips'] = sanitize_textarea_field($input['admin_whitelist_ips'] ?? '');
        $sanitized['custom_whitelist_ips'] = sanitize_textarea_field($input['custom_whitelist_ips'] ?? '');

        do_action('ms_settings_saved', $sanitized, $input);

        return $sanitized;
    }
}
