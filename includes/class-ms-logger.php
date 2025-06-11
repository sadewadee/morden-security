<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Logger {
    private static $instance = null;
    private $log_queue = array();
    private $batch_size = 50;
    private $flush_interval = 30;
    private $core; // Add core instance

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->core = MS_Core::get_instance(); // Initialize core instance

        add_action('wp_footer', array($this, 'flush_log_queue'));
        add_action('admin_footer', array($this, 'flush_log_queue'));
        add_action('wp_ajax_nopriv_ms_flush_logs', array($this, 'ajax_flush_logs'));
        add_action('wp_ajax_ms_flush_logs', array($this, 'ajax_flush_logs'));

        if (!wp_next_scheduled('ms_process_log_queue')) {
            wp_schedule_event(time(), 'every_minute', 'ms_process_log_queue');
        }
        add_action('ms_process_log_queue', array($this, 'process_log_queue'));
    }

    public function queue_log($event_type, $description, $severity = 'medium', $user_id = null, $country = null, $path = null) {
        $this->log_queue[] = array(
            'event_type' => $event_type,
            'description' => $description,
            'severity' => $severity,
            'user_id' => $user_id,
            'country' => $country,
            'path' => $path,
            'ip_address' => $this->core->ms_get_user_ip(), // Use core instance
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'timestamp' => current_time('mysql')
        );

        if (count($this->log_queue) >= $this->batch_size) {
            $this->flush_log_queue();
        }
    }

    public function flush_log_queue() {
        if (empty($this->log_queue)) {
            return;
        }

        wp_remote_post(admin_url('admin-ajax.php'), array(
            'timeout' => 1,
            'blocking' => false,
            'body' => array(
                'action' => 'ms_flush_logs',
                'logs' => base64_encode(serialize($this->log_queue)),
                'nonce' => wp_create_nonce('ms_flush_logs')
            )
        ));

        $this->log_queue = array();
    }

    public function ajax_flush_logs() {
        if (!wp_verify_nonce($_POST['nonce'], 'ms_flush_logs')) {
            wp_die('Invalid nonce');
        }

        $logs = unserialize(base64_decode($_POST['logs']));
        $this->batch_insert_logs($logs);
        wp_die();
    }

    private function batch_insert_logs($logs) {
        global $wpdb;

        if (empty($logs)) {
            return;
        }

        $table_name = $wpdb->prefix . 'ms_security_log';
        $values = array();
        $placeholders = array();

        foreach ($logs as $log) {
            $placeholders[] = "(%s, %s, %s, %s, %s, %s, %s, %s, %s)";
            $values[] = $log['event_type'];
            $values[] = $log['ip_address'];
            $values[] = $log['user_id'];
            $values[] = $log['description'];
            $values[] = $log['severity'];
            $values[] = $log['country'];
            $values[] = $log['path'];
            $values[] = $log['user_agent'];
            $values[] = $log['timestamp'];
        }

        $sql = "INSERT INTO $table_name
                (event_type, ip_address, user_id, description, severity, country, path, user_agent, created_at)
                VALUES " . implode(', ', $placeholders);

        $wpdb->query($wpdb->prepare($sql, $values));
    }

    public function process_log_queue() {
        if (!empty($this->log_queue)) {
            $this->batch_insert_logs($this->log_queue);
            $this->log_queue = array();
        }
    }
}
