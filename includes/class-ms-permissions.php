<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Permissions {

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
    }

    public function get_recommended_permissions() {
        return array(
            'files' => '644',
            'directories' => '755',
            'wp_config' => '600',
            'htaccess' => '644'
        );
    }

    public function get_paths_to_check() {
        $upload_dir = wp_upload_dir();

        return array(
            ABSPATH => array(
                'type' => 'directory',
                'recommended' => '755',
                'description' => 'WordPress Root Directory',
                'critical' => true
            ),
            ABSPATH . 'wp-config.php' => array(
                'type' => 'file',
                'recommended' => '600',
                'description' => 'WordPress Configuration File',
                'critical' => true
            ),
            ABSPATH . '.htaccess' => array(
                'type' => 'file',
                'recommended' => '644',
                'description' => 'Apache Configuration File',
                'critical' => true
            ),
            WP_CONTENT_DIR => array(
                'type' => 'directory',
                'recommended' => '755',
                'description' => 'WordPress Content Directory',
                'critical' => false
            ),
            WP_CONTENT_DIR . '/themes' => array(
                'type' => 'directory',
                'recommended' => '755',
                'description' => 'Themes Directory',
                'critical' => false
            ),
            WP_CONTENT_DIR . '/plugins' => array(
                'type' => 'directory',
                'recommended' => '755',
                'description' => 'Plugins Directory',
                'critical' => false
            ),
            $upload_dir['basedir'] => array(
                'type' => 'directory',
                'recommended' => '755',
                'description' => 'Uploads Directory',
                'critical' => false
            ),
            ABSPATH . 'wp-admin' => array(
                'type' => 'directory',
                'recommended' => '755',
                'description' => 'WordPress Admin Directory',
                'critical' => false
            ),
            ABSPATH . 'wp-includes' => array(
                'type' => 'directory',
                'recommended' => '755',
                'description' => 'WordPress Core Directory',
                'critical' => false
            ),
            ABSPATH . 'index.php' => array(
                'type' => 'file',
                'recommended' => '644',
                'description' => 'WordPress Index File',
                'critical' => false
            ),
            ABSPATH . 'wp-load.php' => array(
                'type' => 'file',
                'recommended' => '644',
                'description' => 'WordPress Load File',
                'critical' => false
            )
        );
    }

    public function scan_permissions() {
        $paths_to_check = $this->get_paths_to_check();
        $issues = array();
        $secure_count = 0;
        $critical_issues = 0;
        $total_checked = 0;

        foreach ($paths_to_check as $path => $config) {
            if (!file_exists($path)) {
                continue;
            }

            $total_checked++;
            $current_perms = $this->get_file_permissions($path);
            $is_secure = ($current_perms === $config['recommended']);
            $is_dangerous = $this->is_dangerous_permission($current_perms);
            $is_writable_by_world = $this->is_world_writable($path);

            if (!$is_secure || $is_dangerous || $is_writable_by_world) {
                $issue = array(
                    'path' => str_replace(ABSPATH, '', $path),
                    'full_path' => $path,
                    'current' => $current_perms,
                    'recommended' => $config['recommended'],
                    'type' => $config['type'],
                    'description' => $config['description'],
                    'dangerous' => $is_dangerous,
                    'world_writable' => $is_writable_by_world,
                    'critical' => $config['critical'],
                    'risk_level' => $this->calculate_risk_level($current_perms, $config)
                );

                $issues[] = $issue;

                if ($config['critical']) {
                    $critical_issues++;
                }
            } else {
                $secure_count++;
            }
        }

        return array(
            'issues' => $issues,
            'secure_count' => $secure_count,
            'total_checked' => $total_checked,
            'critical_issues' => $critical_issues,
            'scan_timestamp' => current_time('mysql'),
            'overall_status' => $this->get_overall_status($issues, $critical_issues)
        );
    }

    private function get_file_permissions($path) {
        $perms = fileperms($path);
        return substr(sprintf('%o', $perms), -3);
    }

    private function is_dangerous_permission($permission) {
        $dangerous_perms = array('777', '666', '776', '767', '677');
        return in_array($permission, $dangerous_perms);
    }

    private function is_world_writable($path) {
        $perms = fileperms($path);
        return ($perms & 0x0002) !== 0;
    }

    private function calculate_risk_level($current_perms, $config) {
        if ($this->is_dangerous_permission($current_perms)) {
            return 'critical';
        }

        if ($config['critical'] && $current_perms !== $config['recommended']) {
            return 'high';
        }

        if ($current_perms !== $config['recommended']) {
            return 'medium';
        }

        return 'low';
    }

    private function get_overall_status($issues, $critical_issues) {
        if ($critical_issues > 0) {
            return 'critical';
        }

        if (count($issues) > 0) {
            return 'warning';
        }

        return 'secure';
    }

    public function fix_permissions($paths_to_fix = null) {
        if ($paths_to_fix === null) {
            $paths_to_fix = array_keys($this->get_paths_to_check());
        }

        $fixed_count = 0;
        $failed_fixes = array();
        $paths_config = $this->get_paths_to_check();
        $detailed_errors = array();

        foreach ($paths_to_fix as $path) {
            if (!file_exists($path)) {
                $failed_fixes[] = array(
                    'path' => str_replace(ABSPATH, '', $path),
                    'description' => 'File/folder does not exist',
                    'error' => 'Path not found'
                );
                continue;
            }

            if (!isset($paths_config[$path])) {
                continue;
            }

            $config = $paths_config[$path];
            $current_perms = $this->get_file_permissions($path);
            $recommended_perms = $config['recommended'];

            if ($current_perms !== $recommended_perms) {
                // Check if we can write to the file/directory
                if (!is_writable($path)) {
                    $failed_fixes[] = array(
                        'path' => str_replace(ABSPATH, '', $path),
                        'description' => $config['description'],
                        'current' => $current_perms,
                        'recommended' => $recommended_perms,
                        'error' => 'Permission denied - file not writable'
                    );
                    continue;
                }

                // Check ownership
                $file_owner = $this->get_file_owner($path);
                $current_user = $this->get_current_process_user();

                if ($file_owner !== $current_user && $file_owner !== 'www-data' && $current_user !== 'root') {
                    $failed_fixes[] = array(
                        'path' => str_replace(ABSPATH, '', $path),
                        'description' => $config['description'],
                        'current' => $current_perms,
                        'recommended' => $recommended_perms,
                        'error' => "Ownership mismatch - Owner: {$file_owner}, Process: {$current_user}"
                    );
                    continue;
                }

                // Attempt to change permissions
                $old_error_reporting = error_reporting(0);
                $result = chmod($path, octdec($recommended_perms));
                error_reporting($old_error_reporting);

                if ($result) {
                    // Verify the change actually took effect
                    clearstatcache(true, $path);
                    $new_perms = $this->get_file_permissions($path);

                    if ($new_perms === $recommended_perms) {
                        $fixed_count++;

                        $this->core->ms_log_security_event('permission_fixed',
                            "Fixed permission for {$config['description']}: {$current_perms} → {$recommended_perms}",
                            'low'
                        );
                    } else {
                        $failed_fixes[] = array(
                            'path' => str_replace(ABSPATH, '', $path),
                            'description' => $config['description'],
                            'current' => $current_perms,
                            'recommended' => $recommended_perms,
                            'error' => "chmod() succeeded but permissions didn't change (Server override)"
                        );
                    }
                } else {
                    $error_msg = error_get_last()['message'] ?? 'chmod() function failed';
                    $failed_fixes[] = array(
                        'path' => str_replace(ABSPATH, '', $path),
                        'description' => $config['description'],
                        'current' => $current_perms,
                        'recommended' => $recommended_perms,
                        'error' => $error_msg
                    );
                }
            }
        }

        return array(
            'fixed_count' => $fixed_count,
            'failed_fixes' => $failed_fixes,
            'server_info' => $this->get_server_info()
        );
    }

    private function get_file_owner($path) {
        if (function_exists('posix_getpwuid') && function_exists('fileowner')) {
            $owner_uid = fileowner($path);
            $owner_info = posix_getpwuid($owner_uid);
            return $owner_info['name'] ?? 'unknown';
        }
        return 'unknown';
    }

    private function get_current_process_user() {
        if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
            $process_uid = posix_geteuid();
            $process_info = posix_getpwuid($process_uid);
            return $process_info['name'] ?? 'unknown';
        }

        if (function_exists('get_current_user')) {
            return get_current_user();
        }

        return 'unknown';
    }

    private function get_server_info() {
        return array(
            'php_user' => $this->get_current_process_user(),
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
            'chmod_available' => function_exists('chmod'),
            'posix_available' => function_exists('posix_getpwuid'),
            'safe_mode' => ini_get('safe_mode') ? 'On' : 'Off',
            'open_basedir' => ini_get('open_basedir') ?: 'Not set'
        );
    }

    public function diagnose_permission_issues() {
        $diagnosis = array();
        $test_path = ABSPATH . 'wp-content';

        // Test basic file operations
        $diagnosis['can_read'] = is_readable($test_path);
        $diagnosis['can_write'] = is_writable($test_path);
        $diagnosis['file_owner'] = $this->get_file_owner($test_path);
        $diagnosis['process_user'] = $this->get_current_process_user();
        $diagnosis['server_info'] = $this->get_server_info();

        // Test chmod function
        $test_file = $test_path . '/ms-permission-test.txt';
        $diagnosis['chmod_test'] = false;

        if (is_writable($test_path)) {
            if (file_put_contents($test_file, 'test')) {
                $old_perms = $this->get_file_permissions($test_file);
                $new_perms = ($old_perms === '644') ? '755' : '644';

                if (chmod($test_file, octdec($new_perms))) {
                    clearstatcache(true, $test_file);
                    $actual_perms = $this->get_file_permissions($test_file);
                    $diagnosis['chmod_test'] = ($actual_perms === $new_perms);
                }

                unlink($test_file);
            }
        }

        return $diagnosis;
    }


    public function get_permission_explanation($permission) {
        $explanations = array(
            '644' => 'Owner: read/write, Group: read, Others: read',
            '755' => 'Owner: read/write/execute, Group: read/execute, Others: read/execute',
            '600' => 'Owner: read/write, Group: none, Others: none',
            '777' => 'Everyone: read/write/execute (DANGEROUS)',
            '666' => 'Everyone: read/write (DANGEROUS)',
            '775' => 'Owner: read/write/execute, Group: read/write/execute, Others: read/execute',
            '664' => 'Owner: read/write, Group: read/write, Others: read'
        );

        return $explanations[$permission] ?? 'Custom permission setting';
    }

    public function get_security_recommendations() {
        return array(
            'critical' => array(
                'wp-config.php should be 600 or 644 (never 777)',
                'Root directory should be 755 (never 777)',
                'No files should be world-writable unless absolutely necessary'
            ),
            'important' => array(
                'All directories should be 755',
                'All files should be 644',
                'Uploads directory should be 755 with PHP execution disabled'
            ),
            'best_practices' => array(
                'Regularly check permissions after updates',
                'Use FTP/SSH for permission changes when possible',
                'Avoid 777 permissions unless temporarily needed',
                'Consider using 600 for wp-config.php for extra security'
            )
        );
    }

    public function deep_scan_directory($directory, $max_depth = 3, $current_depth = 0) {
        if ($current_depth >= $max_depth || !is_dir($directory)) {
            return array();
        }

        $issues = array();
        $iterator = new DirectoryIterator($directory);

        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isDot()) {
                continue;
            }

            $filepath = $fileinfo->getPathname();
            $current_perms = $this->get_file_permissions($filepath);

            if ($fileinfo->isDir()) {
                if ($this->is_dangerous_permission($current_perms)) {
                    $issues[] = array(
                        'path' => str_replace(ABSPATH, '', $filepath),
                        'type' => 'directory',
                        'current' => $current_perms,
                        'recommended' => '755',
                        'dangerous' => true
                    );
                }

                $sub_issues = $this->deep_scan_directory($filepath, $max_depth, $current_depth + 1);
                $issues = array_merge($issues, $sub_issues);
            } else {
                if ($this->is_dangerous_permission($current_perms)) {
                    $issues[] = array(
                        'path' => str_replace(ABSPATH, '', $filepath),
                        'type' => 'file',
                        'current' => $current_perms,
                        'recommended' => '644',
                        'dangerous' => true
                    );
                }
            }
        }

        return $issues;
    }
}
