<?php
class MS_Rate_Limiter {
    private static $instance = null;
    private $rate_limits = array(
        'login_failed' => array('limit' => 10, 'window' => 60),
        'suspicious_request' => array('limit' => 5, 'window' => 60),
        'default' => array('limit' => 20, 'window' => 60)
    );

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function is_rate_limited($event_type, $ip_address) {
        $limits = $this->rate_limits[$event_type] ?? $this->rate_limits['default'];

        $cache_key = "ms_rate_limit_{$event_type}_{$ip_address}";
        $current_count = wp_cache_get($cache_key);

        if ($current_count === false) {
            wp_cache_set($cache_key, 1, '', $limits['window']);
            return false;
        }

        if ($current_count >= $limits['limit']) {
            return true;
        }

        wp_cache_set($cache_key, $current_count + 1, '', $limits['window']);
        return false;
    }

    public function should_log_event($event_type, $ip_address) {
        // During high traffic, be more selective about what we log
        if ($this->is_high_traffic_period()) {
            $priority_events = array('login_lockout', 'ip_blocked', 'core_files_modified');
            return in_array($event_type, $priority_events);
        }

        return !$this->is_rate_limited($event_type, $ip_address);
    }

    private function is_high_traffic_period() {
        $cache_key = 'ms_high_traffic_indicator';
        $traffic_indicator = wp_cache_get($cache_key);

        if ($traffic_indicator === false) {
            // Check current server load
            $load = sys_getloadavg();
            $is_high_traffic = $load[0] > 2.0; // Adjust threshold as needed

            wp_cache_set($cache_key, $is_high_traffic, '', 60);
            return $is_high_traffic;
        }

        return $traffic_indicator;
    }
}
