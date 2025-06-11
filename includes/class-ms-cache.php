<?php
class MS_Cache {
    private static $instance = null;
    private $cache_prefix = 'ms_security_';
    private $cache_expiry = 300; // 5 minutes

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function get_security_stats($force_refresh = false) {
        $cache_key = $this->cache_prefix . 'stats';

        if (!$force_refresh) {
            $cached_stats = wp_cache_get($cache_key);
            if ($cached_stats !== false) {
                return $cached_stats;
            }
        }

        global $wpdb;

        // Use optimized queries with proper indexes
        $stats = array();

        // Login attempts in last 24 hours
        $login_table = $wpdb->prefix . 'ms_login_attempts';
        $stats['login_attempts'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $login_table
             WHERE last_attempt > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
            array()
        ));

        // Blocked IPs count
        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';
        $stats['blocked_ips'] = $wpdb->get_var("SELECT COUNT(*) FROM $blocked_table");

        // Security events in last 24 hours
        $log_table = $wpdb->prefix . 'ms_security_log';
        $stats['security_events'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table
             WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
            array()
        ));

        // Cache for 5 minutes
        wp_cache_set($cache_key, $stats, '', $this->cache_expiry);

        return $stats;
    }

    public function get_recent_logs($limit = 100, $severity = '', $days = 7) {
        $cache_key = $this->cache_prefix . 'logs_' . md5($limit . $severity . $days);

        $cached_logs = wp_cache_get($cache_key);
        if ($cached_logs !== false) {
            return $cached_logs;
        }

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

        // Optimized query with proper joins and indexes
        $query = "SELECT l.*,
                         CASE WHEN b.ip_address IS NOT NULL THEN 1 ELSE 0 END as is_blocked
                  FROM $log_table l
                  LEFT JOIN $blocked_table b ON l.ip_address = b.ip_address
                  WHERE $where_clause
                  ORDER BY l.created_at DESC
                  LIMIT %d";

        $params[] = $limit;

        $logs = $wpdb->get_results($wpdb->prepare($query, $params));

        // Cache for 2 minutes
        wp_cache_set($cache_key, $logs, '', 120);

        return $logs;
    }

    public function invalidate_cache($pattern = '') {
        if (empty($pattern)) {
            wp_cache_flush();
        } else {
            // Invalidate specific cache keys
            $keys_to_delete = array(
                $this->cache_prefix . 'stats',
                $this->cache_prefix . 'logs_*'
            );

            foreach ($keys_to_delete as $key) {
                wp_cache_delete($key);
            }
        }
    }
}
