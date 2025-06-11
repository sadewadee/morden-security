<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Admin {

    private static $instance = null;
    private $core;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->core = MS_Core::get_instance();
        $this->ms_init_admin();
    }

    private function ms_init_admin() {
        add_action('admin_menu', array($this, 'ms_add_admin_menu'));
        add_action('admin_init', array($this, 'ms_register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'ms_enqueue_admin_scripts'));
        add_action('wp_ajax_ms_get_security_stats', array($this, 'ms_get_security_stats'));
        add_action('wp_ajax_ms_get_security_logs', array($this, 'ms_get_security_logs_ajax'));
        add_action('wp_ajax_ms_export_security_logs', array($this, 'ms_export_security_logs'));
        add_action('wp_ajax_ms_unblock_ip', array($this, 'ms_unblock_ip'));
        add_action('wp_ajax_ms_block_ip_from_logs', array($this, 'ms_block_ip_from_logs'));
        add_action('wp_ajax_ms_run_integrity_check', array($this, 'ms_run_integrity_check_ajax'));
        add_action('wp_ajax_ms_get_detailed_report', array($this, 'ms_get_detailed_report_ajax'));
        add_action('wp_ajax_ms_change_db_prefix', array($this, 'ms_change_db_prefix_ajax'));
        add_action('wp_ajax_ms_check_permissions', array($this, 'ms_check_permissions_ajax'));
        add_action('wp_ajax_ms_fix_permissions', array($this, 'ms_fix_permissions_ajax'));
        add_action('wp_ajax_ms_get_firewall_stats', array($this, 'ms_get_firewall_stats_ajax'));
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

        $backup_file = WP_CONTENT_DIR . '/ms-backups/db-backup-' . date('Y-m-d-H-i-s') . '.sql';
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

        $results = $this->scan_file_permissions();
        wp_send_json_success($results);
    }

    private function scan_file_permissions() {
        $paths_to_check = array(
            ABSPATH => array('type' => 'directory', 'recommended' => '755'),
            ABSPATH . 'wp-config.php' => array('type' => 'file', 'recommended' => '644'),
            ABSPATH . '.htaccess' => array('type' => 'file', 'recommended' => '644'),
            WP_CONTENT_DIR => array('type' => 'directory', 'recommended' => '755'),
            WP_CONTENT_DIR . '/themes' => array('type' => 'directory', 'recommended' => '755'),
            WP_CONTENT_DIR . '/plugins' => array('type' => 'directory', 'recommended' => '755'),
            WP_CONTENT_DIR . '/uploads' => array('type' => 'directory', 'recommended' => '755'),
            ABSPATH . 'wp-admin' => array('type' => 'directory', 'recommended' => '755'),
            ABSPATH . 'wp-includes' => array('type' => 'directory', 'recommended' => '755'),
        );

        $issues = array();
        $secure_count = 0;

        foreach ($paths_to_check as $path => $config) {
            if (!file_exists($path)) {
                continue;
            }

            $current_perms = substr(sprintf('%o', fileperms($path)), -3);
            $is_secure = ($current_perms === $config['recommended']);
            $is_dangerous = in_array($current_perms, array('777', '666'));

            if (!$is_secure || $is_dangerous) {
                $issues[] = array(
                    'path' => str_replace(ABSPATH, '', $path),
                    'current' => $current_perms,
                    'recommended' => $config['recommended'],
                    'type' => $config['type'],
                    'dangerous' => $is_dangerous
                );
            } else {
                $secure_count++;
            }
        }

        return array(
            'issues' => $issues,
            'secure_count' => $secure_count,
            'total_checked' => count($paths_to_check)
        );
    }

    public function ms_fix_permissions_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $fixed_count = $this->fix_file_permissions();

        $this->core->ms_log_security_event('permissions_fixed',
            "Fixed {$fixed_count} file/folder permissions",
            'medium',
            get_current_user_id()
        );

        wp_send_json_success(array(
            'message' => sprintf(__('Fixed %d file/folder permissions.', 'morden-security'), $fixed_count)
        ));
    }

    private function fix_file_permissions() {
        $paths_to_fix = array(
            ABSPATH => '755',
            ABSPATH . 'wp-config.php' => '644',
            ABSPATH . '.htaccess' => '644',
            WP_CONTENT_DIR => '755',
            WP_CONTENT_DIR . '/themes' => '755',
            WP_CONTENT_DIR . '/plugins' => '755',
            WP_CONTENT_DIR . '/uploads' => '755',
            ABSPATH . 'wp-admin' => '755',
            ABSPATH . 'wp-includes' => '755',
        );

        $fixed_count = 0;

        foreach ($paths_to_fix as $path => $recommended) {
            if (!file_exists($path)) {
                continue;
            }

            $current_perms = substr(sprintf('%o', fileperms($path)), -3);

            if ($current_perms !== $recommended) {
                if (chmod($path, octdec($recommended))) {
                    $fixed_count++;
                }
            }
        }

        return $fixed_count;
    }

    public function ms_sanitize_settings($input) {
        $sanitized = array();

        $boolean_fields = array(
        'disable_file_editor', 'force_ssl', 'disable_xmlrpc', 'limit_login_attempts',
        'enable_security_headers', 'hide_wp_version', 'remove_wp_credit',
        'hide_wp_logo', 'hide_admin_bar', 'turnstile_enabled', 'enable_2fa',
        'scan_uploads', 'enable_geolocation', 'block_php_uploads', 'disable_pingbacks',
        'enable_bot_protection', 'block_author_scans', 'enable_file_integrity',
        'hide_login_url', 'firewall_auto_block_ip', 'firewall_custom_block_page'
        );

        foreach ($boolean_fields as $field) {
            $sanitized[$field] = isset($input[$field]) ? 1 : 0;
        }

        $sanitized['max_login_attempts'] = absint($input['max_login_attempts'] ?? 5);
        $sanitized['lockout_duration'] = absint($input['lockout_duration'] ?? 1800);
        $sanitized['max_logs'] = min(absint($input['max_logs'] ?? 1000), 10000);
        $sanitized['max_days_retention'] = min(absint($input['max_days_retention'] ?? 30), 365);
        $sanitized['turnstile_site_key'] = sanitize_text_field($input['turnstile_site_key'] ?? '');
        $sanitized['turnstile_secret_key'] = sanitize_text_field($input['turnstile_secret_key'] ?? '');
        $sanitized['6g_block_message'] = sanitize_textarea_field($input['6g_block_message'] ?? 'Access Denied - Your request has been blocked by our security system.');
        $sanitized['custom_safe_folders'] = sanitize_textarea_field($input['custom_safe_folders'] ?? '');
        $sanitized['scan_sensitivity'] = in_array($input['scan_sensitivity'] ?? 'medium', array('low', 'medium', 'high'))
            ? $input['scan_sensitivity'] : 'medium';
        $sanitized['max_scan_file_size'] = min(absint($input['max_scan_file_size'] ?? 10), 100);
            $firewall_mode = sanitize_text_field($input['firewall_mode'] ?? '6g');
    if (!in_array($firewall_mode, array('6g', 'basic', 'disabled'))) {
        $firewall_mode = '6g';
    }
    $sanitized['firewall_mode'] = $firewall_mode;
    $sanitized['enable_6g_firewall'] = ($firewall_mode === '6g') ? 1 : 0;
    $sanitized['enable_basic_firewall'] = ($firewall_mode === 'basic') ? 1 : 0;
    $sanitized['enable_firewall'] = ($firewall_mode !== 'disabled') ? 1 : 0;
    $sanitized['block_suspicious_requests'] = ($firewall_mode !== 'disabled') ? 1 : 0;
    $sanitized['firewall_block_message'] = sanitize_textarea_field($input['firewall_block_message'] ?? 'Access Denied - Your request has been blocked by our security system.');

        return $sanitized;
    }


    public function ms_run_integrity_check_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        try {
            // Run integrity check
            $this->core->ms_run_integrity_check();

            // Get results
            $integrity_results = get_option('ms_integrity_check_results', array());

            if (!empty($integrity_results)) {
                $status = $integrity_results['status'];
                $message = $status === 'clean'
                    ? __('Integrity check completed successfully. No issues found.', 'morden-security')
                    : sprintf(__('Integrity check completed. Found %d modified files and %d missing files.', 'morden-security'),
                        count($integrity_results['modified_files']),
                        count($integrity_results['missing_files']));

                wp_send_json_success(array(
                    'message' => $message,
                    'status' => $status,
                    'results' => $integrity_results
                ));
            } else {
                wp_send_json_error(__('Failed to run integrity check.', 'morden-security'));
            }

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

        $integrity_results = get_option('ms_integrity_check_results', array());
        $plugin_results = get_option('ms_plugin_integrity_results', array());
        $theme_results = get_option('ms_theme_integrity_results', array());

        ob_start();
        ?>
        <div class="ms-detailed-report">
            <h4><?php _e('WordPress Core Integrity', 'morden-security'); ?></h4>
            <?php if (!empty($integrity_results)): ?>
                <p><strong><?php _e('Status:', 'morden-security'); ?></strong>
                    <span class="<?php echo $integrity_results['status'] === 'clean' ? 'ms-status-clean' : 'ms-status-infected'; ?>">
                        <?php echo $integrity_results['status'] === 'clean' ? __('Clean', 'morden-security') : __('Issues Detected', 'morden-security'); ?>
                    </span>
                </p>
                <p><strong><?php _e('Last Check:', 'morden-security'); ?></strong> <?php echo esc_html($integrity_results['last_check']); ?></p>
                <p><strong><?php _e('WordPress Version:', 'morden-security'); ?></strong> <?php echo esc_html($integrity_results['wp_version']); ?></p>

                <?php if (!empty($integrity_results['modified_files'])): ?>
                    <h5><?php _e('Modified Core Files:', 'morden-security'); ?></h5>
                    <ul>
                        <?php foreach ($integrity_results['modified_files'] as $file): ?>
                            <li><code><?php echo esc_html($file); ?></code></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

                <?php if (!empty($integrity_results['missing_files'])): ?>
                    <h5><?php _e('Missing Core Files:', 'morden-security'); ?></h5>
                    <ul>
                        <?php foreach ($integrity_results['missing_files'] as $file): ?>
                            <li><code><?php echo esc_html($file); ?></code></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            <?php else: ?>
                <p><?php _e('No integrity check has been performed yet.', 'morden-security'); ?></p>
            <?php endif; ?>

            <h4><?php _e('Plugin Integrity', 'morden-security'); ?></h4>
            <?php if (!empty($plugin_results['issues'])): ?>
                <?php foreach ($plugin_results['issues'] as $issue): ?>
                    <div class="ms-plugin-issue">
                        <strong><?php echo esc_html($issue['plugin']); ?></strong>
                        <?php if ($issue['issue'] === 'outdated'): ?>
                            <p><?php printf(__('Outdated: Current version %s, Latest version %s', 'morden-security'),
                                esc_html($issue['current']), esc_html($issue['latest'])); ?></p>
                        <?php elseif ($issue['issue'] === 'suspicious_files'): ?>
                            <p><?php _e('Suspicious files detected:', 'morden-security'); ?></p>
                            <ul>
                                <?php foreach ($issue['files'] as $file): ?>
                                    <li><code><?php echo esc_html($file); ?></code></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p><?php _e('No plugin issues detected.', 'morden-security'); ?></p>
            <?php endif; ?>

            <h4><?php _e('Theme Integrity', 'morden-security'); ?></h4>
            <?php if (!empty($theme_results['issues'])): ?>
                <?php foreach ($theme_results['issues'] as $issue): ?>
                    <div class="ms-theme-issue">
                        <strong><?php echo esc_html($issue['theme']); ?></strong>
                        <?php if ($issue['issue'] === 'suspicious_files'): ?>
                            <p><?php _e('Suspicious files detected:', 'morden-security'); ?></p>
                            <ul>
                                <?php foreach ($issue['files'] as $file): ?>
                                    <li><code><?php echo esc_html($file); ?></code></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p><?php _e('No theme issues detected.', 'morden-security'); ?></p>
            <?php endif; ?>
        </div>

        <style>
        .ms-detailed-report h4 {
            color: #23282d;
            border-bottom: 1px solid #ccd0d4;
            padding-bottom: 10px;
            margin-top: 25px;
        }
        .ms-detailed-report h5 {
            color: #555;
            margin-top: 15px;
        }
        .ms-plugin-issue, .ms-theme-issue {
            margin-bottom: 15px;
            padding: 10px;
            background: #f8f9fa;
            border-left: 4px solid #007cba;
            border-radius: 0 4px 4px 0;
        }
        .ms-status-clean {
            color: #155724;
            font-weight: bold;
        }
        .ms-status-infected {
            color: #721c24;
            font-weight: bold;
        }
        </style>
        <?php
        $content = ob_get_clean();

        wp_send_json_success(array('content' => $content));
    }


    public function ms_add_admin_menu() {
        add_menu_page(
            __('Morden Security', 'morden-security'),
            __('Morden Security', 'morden-security'),
            'manage_options',
            'morden-security',
            array($this, 'ms_admin_page'),
            'dashicons-shield-alt',
            30
        );

        add_submenu_page(
            'morden-security',
            __('Security Logs', 'morden-security'),
            __('Security Logs', 'morden-security'),
            'manage_options',
            'ms-security-logs',
            array($this, 'ms_security_logs_page')
        );

        add_submenu_page(
            'morden-security',
            __('Blocked IPs', 'morden-security'),
            __('Blocked IPs', 'morden-security'),
            'manage_options',
            'ms-blocked-ips',
            array($this, 'ms_blocked_ips_page')
        );
    }

    public function ms_register_settings() {
        register_setting('ms_settings_group', 'ms_settings', array($this, 'ms_sanitize_settings'));
    }

    public function ms_enqueue_admin_scripts($hook) {
        // Only load on Morden Security pages
        $allowed_pages = array(
            'toplevel_page_morden-security',
            'morden-security_page_ms-security-logs',
            'morden-security_page_ms-blocked-ips'
        );

        if (!in_array($hook, $allowed_pages)) {
            return;
        }

        // Enqueue CSS
        wp_enqueue_style(
            'ms-admin-style',
            MS_PLUGIN_URL . 'admin/css/admin-style.css',
            array(),
            MS_VERSION
        );

        // Enqueue JavaScript
        wp_enqueue_script(
            'ms-admin-script',
            MS_PLUGIN_URL . 'admin/js/admin-script.js',
            array('jquery'),
            MS_VERSION,
            true
        );

        // Localize script
        wp_localize_script('ms-admin-script', 'ms_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ms_admin_nonce'),
            'confirm_block_ip' => __('Are you sure you want to block this IP address?', 'morden-security'),
            'confirm_unblock_ip' => __('Are you sure you want to unblock this IP address?', 'morden-security'),
            'blocking_ip' => __('Blocking IP...', 'morden-security'),
            'unblocking_ip' => __('Unblocking...', 'morden-security'),
            'block_ip' => __('Block IP', 'morden-security'),
            'unblock' => __('Unblock', 'morden-security')
        ));

        // Add inline CSS for immediate styling
        $inline_css = '
            .ms-tabs .nav-tab-wrapper {
                border-bottom: 1px solid #ccd0d4;
                margin: 0;
                padding: 0;
            }

            .ms-tabs .nav-tab {
                border: 1px solid #ccd0d4;
                border-bottom: none;
                background: #f1f1f1;
                color: #666;
                text-decoration: none;
                padding: 8px 12px;
                margin: 0 2px -1px 0;
                display: inline-block;
            }

            .ms-tabs .nav-tab.nav-tab-active {
                background: #fff;
                color: #000;
                border-bottom: 1px solid #fff;
                margin-bottom: -1px;
            }

            .ms-tabs .tab-content {
                display: none;
                padding: 20px;
                background: #fff;
                border: 1px solid #ccd0d4;
                border-top: none;
            }

            .ms-tabs .tab-content.active {
                display: block;
            }

            .ms-block-ip-btn {
                background: #dc3545;
                color: #fff;
                border: none;
                padding: 4px 8px;
                border-radius: 3px;
                cursor: pointer;
                font-size: 12px;
                margin-left: 5px;
            }

            .ms-block-ip-btn:hover {
                background: #c82333;
            }

            .ms-block-ip-btn:disabled {
                background: #6c757d;
                cursor: not-allowed;
            }
        ';

        wp_add_inline_style('ms-admin-style', $inline_css);
    }

    public function ms_admin_page() {
        include MS_PLUGIN_PATH . 'admin/admin-page.php';
    }

    public function ms_security_logs_page() {
        global $wpdb;

        $options = get_option('ms_settings', array());
        $max_logs = isset($options['max_logs']) ? min(absint($options['max_logs']), 10000) : 1000;

        echo '<div class="wrap">';
        echo '<h1>' . __('Security Logs', 'morden-security') . '</h1>';

        // Filters
        echo '<div class="ms-logs-filters">';
        echo '<form method="get" id="ms-logs-filter">';
        echo '<input type="hidden" name="page" value="ms-security-logs">';
        echo '<select name="severity" id="ms-severity-filter">';
        echo '<option value="">' . __('All Severities', 'morden-security') . '</option>';
        echo '<option value="low">' . __('Low', 'morden-security') . '</option>';
        echo '<option value="medium">' . __('Medium', 'morden-security') . '</option>';
        echo '<option value="high">' . __('High', 'morden-security') . '</option>';
        echo '<option value="critical">' . __('Critical', 'morden-security') . '</option>';
        echo '</select>';

        echo '<select name="days" id="ms-days-filter">';
        echo '<option value="1">' . __('Last 24 hours', 'morden-security') . '</option>';
        echo '<option value="7" selected>' . __('Last 7 days', 'morden-security') . '</option>';
        echo '<option value="30">' . __('Last 30 days', 'morden-security') . '</option>';
        echo '</select>';

        echo '<input type="number" name="limit" id="ms-limit-filter" value="100" min="10" max="' . $max_logs . '" placeholder="' . __('Limit', 'morden-security') . '">';
        echo '<button type="button" id="ms-filter-logs" class="button">' . __('Filter', 'morden-security') . '</button>';
        echo '<button type="button" id="ms-export-logs" class="button">' . __('Export CSV', 'morden-security') . '</button>';
        echo '</form>';
        echo '</div>';

        echo '<div id="ms-logs-container">';
        echo '<table class="wp-list-table widefat fixed striped" id="ms-logs-table">';
        echo '<thead><tr>';
        echo '<th>' . __('Date/Time', 'morden-security') . '</th>';
        echo '<th>' . __('Event Type', 'morden-security') . '</th>';
        echo '<th>' . __('IP Address', 'morden-security') . '</th>';
        echo '<th>' . __('Country', 'morden-security') . '</th>';
        echo '<th>' . __('Path', 'morden-security') . '</th>';
        echo '<th>' . __('Description', 'morden-security') . '</th>';
        echo '<th>' . __('Severity', 'morden-security') . '</th>';
        echo '<th>' . __('Actions', 'morden-security') . '</th>';
        echo '</tr></thead>';
        echo '<tbody id="ms-logs-tbody">';
        echo '<tr><td colspan="8">' . __('Loading...', 'morden-security') . '</td></tr>';
        echo '</tbody></table>';
        echo '</div>';

        echo '<div id="ms-logs-pagination"></div>';
        echo '</div>';
    }

    public function ms_blocked_ips_page() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'ms_blocked_ips';
        $blocked_ips = $wpdb->get_results("SELECT * FROM $table_name ORDER BY created_at DESC");

        echo '<div class="wrap">';
        echo '<h1>' . __('Blocked IP Addresses', 'morden-security') . '</h1>';
        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th>' . __('IP Address', 'morden-security') . '</th>';
        echo '<th>' . __('Reason', 'morden-security') . '</th>';
        echo '<th>' . __('Blocked Until', 'morden-security') . '</th>';
        echo '<th>' . __('Permanent', 'morden-security') . '</th>';
        echo '<th>' . __('Actions', 'morden-security') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($blocked_ips as $ip) {
            echo '<tr>';
            echo '<td>' . esc_html($ip->ip_address) . '</td>';
            echo '<td>' . esc_html($ip->reason) . '</td>';
            echo '<td>' . esc_html($ip->blocked_until ?: __('Permanent', 'morden-security')) . '</td>';
            echo '<td>' . ($ip->permanent ? __('Yes', 'morden-security') : __('No', 'morden-security')) . '</td>';
            echo '<td><button class="button ms-unblock-ip" data-ip="' . esc_attr($ip->ip_address) . '">' . __('Unblock', 'morden-security') . '</button></td>';
            echo '</tr>';
        }

        echo '</tbody></table>';
        echo '</div>';
    }

    public function ms_get_security_stats() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        global $wpdb;

        $stats = array();

        // Get login attempts in last 24 hours
        $login_table = $wpdb->prefix . 'ms_login_attempts';
        $stats['login_attempts'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $login_table WHERE last_attempt > %s",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));

        // Get blocked IPs count
        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';
        $stats['blocked_ips'] = $wpdb->get_var("SELECT COUNT(*) FROM $blocked_table");

        // Get security events in last 24 hours
        $log_table = $wpdb->prefix . 'ms_security_log';
        $stats['security_events'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table WHERE created_at > %s",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));

        wp_send_json_success($stats);
    }

    public function ms_get_security_logs_ajax() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        global $wpdb;

        $options = get_option('ms_settings', array());
        $max_logs = isset($options['max_logs']) ? min(absint($options['max_logs']), 10000) : 1000;
        $max_days = isset($options['max_days_retention']) ? min(absint($options['max_days_retention']), 365) : 30;

        $limit = isset($_POST['limit']) ? min(absint($_POST['limit']), $max_logs) : 100;
        $days = isset($_POST['days']) ? min(absint($_POST['days']), $max_days) : 7;
        $severity = isset($_POST['severity']) ? sanitize_text_field($_POST['severity']) : '';
        $offset = isset($_POST['offset']) ? absint($_POST['offset']) : 0;

        $log_table = $wpdb->prefix . 'ms_security_log';
        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';

        // FIX: Gunakan alias table untuk menghindari ambiguous column
        $where_clause = "WHERE l.created_at > %s";
        $params = array(date('Y-m-d H:i:s', strtotime('-' . $days . ' days')));

        if (!empty($severity)) {
            $where_clause .= " AND l.severity = %s";
            $params[] = $severity;
        }

        // Get total count dengan alias yang jelas
        $total_query = "SELECT COUNT(*) FROM $log_table l $where_clause";
        $total = $wpdb->get_var($wpdb->prepare($total_query, $params));

        // Get logs dengan alias yang jelas untuk semua kolom
        $logs_query = "SELECT l.*,
                            CASE WHEN b.ip_address IS NOT NULL THEN 1 ELSE 0 END as is_blocked
                    FROM $log_table l
                    LEFT JOIN $blocked_table b ON l.ip_address = b.ip_address
                    $where_clause
                    ORDER BY l.created_at DESC
                    LIMIT %d OFFSET %d";
        $params[] = $limit;
        $params[] = $offset;

        $logs = $wpdb->get_results($wpdb->prepare($logs_query, $params));

        wp_send_json_success(array(
            'logs' => $logs,
            'total' => $total,
            'limit' => $limit,
            'offset' => $offset
        ));
    }


    public function ms_block_ip_from_logs() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'morden-security'));
            return;
        }

        $ip = sanitize_text_field($_POST['ip'] ?? '');
        $reason = sanitize_text_field($_POST['reason'] ?? 'Blocked from security logs');

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(__('Invalid IP address.', 'morden-security'));
            return;
        }

        // Check if IP is already blocked
        global $wpdb;
        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $blocked_table WHERE ip_address = %s",
            $ip
        ));

        if ($existing) {
            wp_send_json_error(__('IP address is already blocked.', 'morden-security'));
            return;
        }

        // Block the IP
        $result = $wpdb->insert(
            $blocked_table,
            array(
                'ip_address' => $ip,
                'reason' => $reason,
                'blocked_until' => null, // Permanent block
                'permanent' => 1,
                'created_at' => current_time('mysql')
            )
        );

        if ($result) {
            // Log the blocking action
            $this->core->ms_log_security_event('ip_blocked_manual',
                "IP manually blocked from security logs: $ip - Reason: $reason",
                'high',
                get_current_user_id()
            );

            wp_send_json_success(__('IP address has been blocked successfully.', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to block IP address.', 'morden-security'));
        }
    }

    public function ms_export_security_logs() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        global $wpdb;

        $options = get_option('ms_settings', array());
        $max_logs = isset($options['max_logs']) ? min(absint($options['max_logs']), 10000) : 1000;
        $max_days = isset($options['max_days_retention']) ? min(absint($options['max_days_retention']), 365) : 30;

        $limit = isset($_GET['limit']) ? min(absint($_GET['limit']), $max_logs) : 1000;
        $days = isset($_GET['days']) ? min(absint($_GET['days']), $max_days) : 7;
        $severity = isset($_GET['severity']) ? sanitize_text_field($_GET['severity']) : '';

        $log_table = $wpdb->prefix . 'ms_security_log';

        // FIX: Gunakan alias table untuk menghindari ambiguous column
        $where_clause = "WHERE l.created_at > %s";
        $params = array(date('Y-m-d H:i:s', strtotime('-' . $days . ' days')));

        if (!empty($severity)) {
            $where_clause .= " AND l.severity = %s";
            $params[] = $severity;
        }

        $logs_query = "SELECT l.* FROM $log_table l $where_clause ORDER BY l.created_at DESC LIMIT %d";
        $params[] = $limit;

        $logs = $wpdb->get_results($wpdb->prepare($logs_query, $params));

        // Set headers for CSV download
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="security-logs-' . date('Y-m-d') . '.csv"');

        $output = fopen('php://output', 'w');

        // CSV headers
        fputcsv($output, array(
            'Date/Time',
            'Event Type',
            'IP Address',
            'Country',
            'Path',
            'Description',
            'Severity',
            'User Agent'
        ));

        // CSV data
        foreach ($logs as $log) {
            fputcsv($output, array(
                $log->created_at,
                $log->event_type,
                $log->ip_address,
                $log->country ?: 'Unknown',
                $log->path ?: '-',
                $log->description,
                $log->severity,
                $log->user_agent ?: '-'
            ));
        }

        fclose($output);
        exit;
    }

    public function ms_unblock_ip() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        $ip = sanitize_text_field($_POST['ip']);

        global $wpdb;
        $table_name = $wpdb->prefix . 'ms_blocked_ips';

        $result = $wpdb->delete($table_name, array('ip_address' => $ip));

        if ($result) {
            $this->core->ms_log_security_event('ip_unblocked',
                "IP unblocked by admin: $ip",
                'low',
                get_current_user_id()
            );
            wp_send_json_success(__('IP address unblocked successfully.', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to unblock IP address.', 'morden-security'));
        }
    }
}
