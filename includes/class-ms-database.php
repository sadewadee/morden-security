<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Database {

    private static $instance = null;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public static function create_all_tables() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        $login_table = $wpdb->prefix . 'ms_login_attempts';
        $sql1 = "CREATE TABLE $login_table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            username varchar(60) NOT NULL,
            attempts int(11) NOT NULL DEFAULT 1,
            locked_until datetime DEFAULT NULL,
            last_attempt datetime DEFAULT CURRENT_TIMESTAMP,
            user_agent text,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY locked_until (locked_until)
        ) $charset_collate ENGINE=InnoDB;";

        $log_table = $wpdb->prefix . 'ms_security_log';
        $sql2 = "CREATE TABLE $log_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            ip_address varchar(45) NOT NULL,
            user_id bigint(20) DEFAULT NULL,
            description text NOT NULL,
            severity enum('low','medium','high','critical') DEFAULT 'medium',
            country varchar(10) DEFAULT NULL,
            path varchar(255) DEFAULT NULL,
            user_agent text DEFAULT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY ip_address (ip_address),
            KEY severity (severity),
            KEY created_at (created_at),
            KEY composite_idx (created_at, severity, event_type),
            KEY ip_time_idx (ip_address, created_at)
        ) $charset_collate ENGINE=InnoDB ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=8;";

        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';
        $sql3 = "CREATE TABLE $blocked_table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            reason text NOT NULL,
            blocked_until datetime DEFAULT NULL,
            permanent tinyint(1) DEFAULT 0,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address),
            KEY blocked_until (blocked_until)
        ) $charset_collate ENGINE=InnoDB;";

        $integrity_table = $wpdb->prefix . 'ms_file_integrity';
        $sql4 = "CREATE TABLE $integrity_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path varchar(500) NOT NULL,
            file_hash varchar(64) NOT NULL,
            file_size bigint(20) NOT NULL,
            last_modified datetime NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY file_path (file_path),
            KEY last_modified (last_modified)
        ) $charset_collate ENGINE=InnoDB;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql1);
        dbDelta($sql2);
        dbDelta($sql3);
        dbDelta($sql4);
    }

    public static function optimize_tables() {
        global $wpdb;

        $tables = array(
            $wpdb->prefix . 'ms_security_log',
            $wpdb->prefix . 'ms_login_attempts',
            $wpdb->prefix . 'ms_blocked_ips',
            $wpdb->prefix . 'ms_file_integrity'
        );

        foreach ($tables as $table) {
            $wpdb->query("OPTIMIZE TABLE $table");
        }
    }

    public static function add_missing_indexes() {
        global $wpdb;

        $log_table = $wpdb->prefix . 'ms_security_log';

        $existing_indexes = $wpdb->get_results("SHOW INDEX FROM $log_table", ARRAY_A);
        $index_names = array_column($existing_indexes, 'Key_name');

        if (!in_array('country', $index_names)) {
            $wpdb->query("ALTER TABLE $log_table ADD INDEX country (country)");
        }

        if (!in_array('composite_idx', $index_names)) {
            $wpdb->query("ALTER TABLE $log_table ADD INDEX composite_idx (created_at, severity, event_type)");
        }

        if (!in_array('ip_time_idx', $index_names)) {
            $wpdb->query("ALTER TABLE $log_table ADD INDEX ip_time_idx (ip_address, created_at)");
        }
    }

    public static function add_missing_columns() {
        global $wpdb;

        $log_table = $wpdb->prefix . 'ms_security_log';

        $columns = $wpdb->get_results("SHOW COLUMNS FROM $log_table", ARRAY_A);
        $column_names = array_column($columns, 'Field');

        if (!in_array('country', $column_names)) {
            $wpdb->query("ALTER TABLE $log_table ADD COLUMN country varchar(10) DEFAULT NULL");
        }

        if (!in_array('path', $column_names)) {
            $wpdb->query("ALTER TABLE $log_table ADD COLUMN path varchar(255) DEFAULT NULL");
        }
    }

    private function create_database_backup($backup_file) {
        return MS_Database::create_database_backup($backup_file);
    }

private function change_database_prefix($new_prefix) {
    global $wpdb;

    $old_prefix = $wpdb->prefix;

    $tables = $wpdb->get_results("SHOW TABLES LIKE '{$old_prefix}%'", ARRAY_N);

    if (empty($tables)) {
        throw new Exception('No tables found with current prefix.');
    }

    $backup_file = WP_CONTENT_DIR . '/ms-db-backup-' . date('Y-m-d-H-i-s') . '.sql';
    $this->create_database_backup($backup_file);

    foreach ($tables as $table) {
        $old_table = $table[0];
        $new_table = str_replace($old_prefix, $new_prefix, $old_table);

        $result = $wpdb->query("RENAME TABLE `{$old_table}` TO `{$new_table}`");
        if ($result === false) {
            throw new Exception("Failed to rename table {$old_table}");
        }
    }

    MS_Database::change_table_prefix($old_prefix, $new_prefix);
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


    public static function cleanup_old_data($max_days = 30, $max_logs = 1000) {
        global $wpdb;

        $log_table = $wpdb->prefix . 'ms_security_log';
        $login_table = $wpdb->prefix . 'ms_login_attempts';

        $wpdb->query($wpdb->prepare(
            "DELETE FROM $login_table WHERE last_attempt < %s",
            date('Y-m-d H:i:s', strtotime('-' . $max_days . ' days'))
        ));

        $wpdb->query($wpdb->prepare(
            "DELETE FROM $log_table WHERE created_at < %s",
            date('Y-m-d H:i:s', strtotime('-' . $max_days . ' days'))
        ));

        $total_logs = $wpdb->get_var("SELECT COUNT(*) FROM $log_table");
        if ($total_logs > $max_logs) {
            $offset = $total_logs - $max_logs;
            $wpdb->query("DELETE FROM $log_table ORDER BY created_at ASC LIMIT $offset");
        }
    }

    public static function change_table_prefix($old_prefix, $new_prefix) {
        global $wpdb;

        $tables = array(
            'ms_security_log',
            'ms_login_attempts',
            'ms_blocked_ips',
            'ms_file_integrity'
        );

        foreach ($tables as $table) {
            $old_table = $old_prefix . $table;
            $new_table = $new_prefix . $table;

            $result = $wpdb->query("RENAME TABLE `{$old_table}` TO `{$new_table}`");
            if ($result === false) {
                throw new Exception("Failed to rename table {$old_table}");
            }
        }

        return true;
    }
}
