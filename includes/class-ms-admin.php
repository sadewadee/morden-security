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

    public function ms_sanitize_settings($input) {
        $sanitized = array();

        $boolean_fields = array(
            'disable_file_editor', 'force_ssl', 'disable_xmlrpc', 'limit_login_attempts',
            'enable_security_headers', 'hide_wp_version', 'remove_wp_credit',
            'hide_wp_logo', 'hide_admin_bar', 'turnstile_enabled', 'enable_2fa',
            'block_suspicious_requests', 'enable_firewall', 'scan_uploads', 'enable_geolocation'
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

        // New scan settings
        $sanitized['custom_safe_folders'] = sanitize_textarea_field($input['custom_safe_folders'] ?? '');
        $sanitized['scan_sensitivity'] = in_array($input['scan_sensitivity'] ?? 'medium', array('low', 'medium', 'high'))
            ? $input['scan_sensitivity'] : 'medium';
        $sanitized['max_scan_file_size'] = min(absint($input['max_scan_file_size'] ?? 10), 100);

        return $sanitized;
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
            'nonce' => wp_create_nonce('ms_admin_nonce')
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
        ';

        wp_add_inline_style('ms-admin-style', $inline_css);
    }

    public function ms_admin_page() {
        // Force load CSS jika belum ter-load
        if (!wp_style_is('ms-admin-style', 'enqueued')) {
            echo '<link rel="stylesheet" href="' . MS_PLUGIN_URL . 'admin/css/admin-style.css?v=' . MS_VERSION . '">';
        }

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

        echo '<input type="number" name="limit" id="ms-limit-filter" value="20" min="10" max="' . $max_logs . '" placeholder="' . __('Limit', 'morden-security') . '">';
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
        echo '</tr></thead>';
        echo '<tbody id="ms-logs-tbody">';
        echo '<tr><td colspan="7">' . __('Loading...', 'morden-security') . '</td></tr>';
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

        $where_clause = "WHERE created_at > %s";
        $params = array(date('Y-m-d H:i:s', strtotime('-' . $days . ' days')));

        if (!empty($severity)) {
            $where_clause .= " AND severity = %s";
            $params[] = $severity;
        }

        // Get total count
        $total_query = "SELECT COUNT(*) FROM $log_table $where_clause";
        $total = $wpdb->get_var($wpdb->prepare($total_query, $params));

        // Get logs
        $logs_query = "SELECT * FROM $log_table $where_clause ORDER BY created_at DESC LIMIT %d OFFSET %d";
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

        $where_clause = "WHERE created_at > %s";
        $params = array(date('Y-m-d H:i:s', strtotime('-' . $days . ' days')));

        if (!empty($severity)) {
            $where_clause .= " AND severity = %s";
            $params[] = $severity;
        }

        $logs_query = "SELECT * FROM $log_table $where_clause ORDER BY created_at DESC LIMIT %d";
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

    public function ms_manual_scan() {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }

        try {
            // Run the security scan
            $this->core->ms_run_security_scan();

            // Get scan results
            global $wpdb;
            $log_table = $wpdb->prefix . 'ms_security_log';

            $recent_events = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM $log_table WHERE created_at > %s AND event_type = 'suspicious_file'",
                date('Y-m-d H:i:s', strtotime('-1 minute'))
            ));

            $message = sprintf(
                __('Manual scan completed successfully. %d suspicious files detected.', 'morden-security'),
                $recent_events
            );

            wp_send_json_success(array('message' => $message));

        } catch (Exception $e) {
            wp_send_json_error('Scan failed: ' . $e->getMessage());
        }
    }

}