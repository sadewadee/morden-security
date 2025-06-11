<?php
class MS_Maintenance {

    public function __construct() {
        // Schedule maintenance tasks
        if (!wp_next_scheduled('ms_database_maintenance')) {
            wp_schedule_event(time(), 'daily', 'ms_database_maintenance');
        }
        add_action('ms_database_maintenance', array($this, 'run_maintenance'));
    }

    public function run_maintenance() {
        global $wpdb;

        // Optimize tables
        $tables = array(
            $wpdb->prefix . 'ms_security_log',
            $wpdb->prefix . 'ms_login_attempts',
            $wpdb->prefix . 'ms_blocked_ips'
        );

        foreach ($tables as $table) {
            $wpdb->query("OPTIMIZE TABLE $table");
        }

        // Clean old logs
        $this->cleanup_old_logs();

        // Update statistics
        $this->update_statistics();
    }

    private function cleanup_old_logs() {
        global $wpdb;

        $options = get_option('ms_settings', array());
        $max_days = $options['max_days_retention'] ?? 30;
        $max_logs = $options['max_logs'] ?? 1000;

        $log_table = $wpdb->prefix . 'ms_security_log';

        // Delete old logs by date
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $log_table WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $max_days
        ));

        // Limit total logs
        $total_logs = $wpdb->get_var("SELECT COUNT(*) FROM $log_table");
        if ($total_logs > $max_logs) {
            $offset = $total_logs - $max_logs;
            $wpdb->query("DELETE FROM $log_table ORDER BY created_at ASC LIMIT $offset");
        }

        // Clear cache after cleanup
        MS_Cache::get_instance()->invalidate_cache();
    }
}
