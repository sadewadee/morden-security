<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Integrity_Checker {

    private $core;
    private $wp_version;
    private $wp_checksums;

    public function __construct() {
        $this->core = MS_Core::get_instance();
        $this->wp_version = get_bloginfo('version');
    }

    public function check_wordpress_integrity() {
        $results = array(
            'status' => 'clean',
            'wp_version' => $this->wp_version,
            'last_check' => current_time('mysql'),
            'modified_files' => array(),
            'missing_files' => array(),
            'unknown_files' => array(),
            'total_checked' => 0,
            'scan_duration' => 0
        );

        $start_time = microtime(true);

        try {
            // Get WordPress checksums
            $this->wp_checksums = $this->get_wordpress_checksums();

            if (!$this->wp_checksums) {
                throw new Exception('Unable to retrieve WordPress checksums');
            }

            // Check core files
            $this->check_core_files($results);

            // Check for unknown files in root directory
            $this->check_unknown_files($results);

            // Determine overall status
            if (!empty($results['modified_files']) || !empty($results['missing_files']) || !empty($results['unknown_files'])) {
                $results['status'] = 'infected';
            }

        } catch (Exception $e) {
            $results['status'] = 'error';
            $results['error'] = $e->getMessage();
        }

        $results['scan_duration'] = round(microtime(true) - $start_time, 2);

        return $results;
    }

    private function get_wordpress_checksums() {
        $api_url = "https://api.wordpress.org/core/checksums/1.0/?version={$this->wp_version}";

        $response = wp_remote_get($api_url, array(
            'timeout' => 30,
            'user-agent' => 'Morden Security Plugin/1.4.0'
        ));

        if (is_wp_error($response)) {
            return false;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!isset($data['checksums'])) {
            return false;
        }

        return $data['checksums'];
    }

    private function check_core_files(&$results) {
        foreach ($this->wp_checksums as $file => $expected_hash) {
            $file_path = ABSPATH . $file;
            $results['total_checked']++;

            if (!file_exists($file_path)) {
                $results['missing_files'][] = $file;
                continue;
            }

            // Calculate file hash
            $actual_hash = md5_file($file_path);

            if ($actual_hash !== $expected_hash) {
                $results['modified_files'][] = array(
                    'file' => $file,
                    'expected_hash' => $expected_hash,
                    'actual_hash' => $actual_hash,
                    'size' => filesize($file_path),
                    'modified_time' => date('Y-m-d H:i:s', filemtime($file_path))
                );
            }
        }
    }

    private function check_unknown_files(&$results) {
        $root_files = glob(ABSPATH . '*.php');
        $allowed_root_files = array(
            'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
            'wp-config-sample.php', 'wp-config.php', 'wp-cron.php', 'wp-links-opml.php',
            'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php',
            'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php'
        );

        foreach ($root_files as $file_path) {
            $filename = basename($file_path);

            // Skip allowed files and wp-config.php
            if (in_array($filename, $allowed_root_files)) {
                continue;
            }

            // Check if it's a known WordPress core file
            $relative_path = str_replace(ABSPATH, '', $file_path);
            if (!isset($this->wp_checksums[$relative_path])) {
                $results['unknown_files'][] = array(
                    'file' => $relative_path,
                    'size' => filesize($file_path),
                    'modified_time' => date('Y-m-d H:i:s', filemtime($file_path)),
                    'permissions' => substr(sprintf('%o', fileperms($file_path)), -4)
                );
            }
        }
    }

    public function scan_file_for_malware($file_path) {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }

        $content = file_get_contents($file_path, false, null, 0, 1024 * 1024); // Read max 1MB

        if ($content === false) {
            return false;
        }

        // Malware patterns
        $malware_patterns = array(
            // PHP malware
            '/eval\s*\(\s*base64_decode/i',
            '/eval\s*\(\s*gzinflate/i',
            '/eval\s*\(\s*str_rot13/i',
            '/eval\s*\(\s*gzuncompress/i',
            '/system\s*\(\s*base64_decode/i',
            '/exec\s*\(\s*base64_decode/i',
            '/shell_exec\s*\(\s*base64_decode/i',
            '/passthru\s*\(\s*base64_decode/i',

            // Common backdoor signatures
            '/c99shell/i',
            '/r57shell/i',
            '/webshell/i',
            '/backdoor/i',
            '/wp-vcd/i',
            '/hello\.php.*wp_vcd/i',

            // Suspicious functions
            '/file_get_contents\s*\(\s*["\']https?:\/\//i',
            '/curl_exec\s*\(/i',
            '/wp_remote_get\s*\(\s*\$_/i',

            // Obfuscated code
            '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'][A-Za-z0-9+\/]{50,}["\'];/i',
            '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(/i',

            // Suspicious WordPress hooks
            '/add_action\s*\(\s*["\']wp_head["\'].*base64/i',
            '/add_action\s*\(\s*["\']init["\'].*eval/i'
        );

        foreach ($malware_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    public function get_file_hash($file_path) {
        if (!file_exists($file_path)) {
            return false;
        }

        return md5_file($file_path);
    }

    public function create_baseline() {
        $baseline = array(
            'created_at' => current_time('mysql'),
            'wp_version' => $this->wp_version,
            'files' => array()
        );

        // Get all core files
        $core_files = array_merge(
            glob(ABSPATH . '*.php'),
            glob(ABSPATH . 'wp-admin/**/*.php', GLOB_BRACE),
            glob(ABSPATH . 'wp-includes/**/*.php', GLOB_BRACE)
        );

        foreach ($core_files as $file_path) {
            $relative_path = str_replace(ABSPATH, '', $file_path);
            $baseline['files'][$relative_path] = array(
                'hash' => md5_file($file_path),
                'size' => filesize($file_path),
                'modified' => filemtime($file_path)
            );
        }

        update_option('ms_integrity_baseline', $baseline);

        return $baseline;
    }

    public function compare_with_baseline() {
        $baseline = get_option('ms_integrity_baseline');

        if (!$baseline) {
            return array('error' => 'No baseline found. Please create a baseline first.');
        }

        $results = array(
            'status' => 'clean',
            'baseline_date' => $baseline['created_at'],
            'changes' => array(),
            'new_files' => array(),
            'deleted_files' => array()
        );

        // Check existing files
        foreach ($baseline['files'] as $file => $baseline_data) {
            $file_path = ABSPATH . $file;

            if (!file_exists($file_path)) {
                $results['deleted_files'][] = $file;
                continue;
            }

            $current_hash = md5_file($file_path);
            $current_size = filesize($file_path);
            $current_modified = filemtime($file_path);

            if ($current_hash !== $baseline_data['hash'] ||
                $current_size !== $baseline_data['size'] ||
                $current_modified !== $baseline_data['modified']) {

                $results['changes'][] = array(
                    'file' => $file,
                    'type' => 'modified',
                    'baseline_hash' => $baseline_data['hash'],
                    'current_hash' => $current_hash,
                    'baseline_size' => $baseline_data['size'],
                    'current_size' => $current_size
                );
            }
        }

        // Check for new files
        $current_files = array_merge(
            glob(ABSPATH . '*.php'),
            glob(ABSPATH . 'wp-admin/**/*.php', GLOB_BRACE),
            glob(ABSPATH . 'wp-includes/**/*.php', GLOB_BRACE)
        );

        foreach ($current_files as $file_path) {
            $relative_path = str_replace(ABSPATH, '', $file_path);

            if (!isset($baseline['files'][$relative_path])) {
                $results['new_files'][] = array(
                    'file' => $relative_path,
                    'hash' => md5_file($file_path),
                    'size' => filesize($file_path),
                    'created' => date('Y-m-d H:i:s', filemtime($file_path))
                );
            }
        }

        // Determine status
        if (!empty($results['changes']) || !empty($results['new_files']) || !empty($results['deleted_files'])) {
            $results['status'] = 'changed';
        }

        return $results;
    }

    public function get_detailed_report() {
        $integrity_results = get_option('ms_integrity_check_results', array());

        if (empty($integrity_results)) {
            return array('error' => 'No integrity check results found.');
        }

        $report = array(
            'summary' => array(
                'status' => $integrity_results['status'],
                'wp_version' => $integrity_results['wp_version'],
                'last_check' => $integrity_results['last_check'],
                'total_checked' => $integrity_results['total_checked'],
                'scan_duration' => $integrity_results['scan_duration']
            ),
            'issues' => array(),
            'recommendations' => array()
        );

        // Process modified files
        if (!empty($integrity_results['modified_files'])) {
            foreach ($integrity_results['modified_files'] as $file) {
                $report['issues'][] = array(
                    'type' => 'modified',
                    'severity' => 'high',
                    'file' => $file['file'],
                    'description' => 'Core file has been modified',
                    'details' => $file
                );
            }
        }

        // Process missing files
        if (!empty($integrity_results['missing_files'])) {
            foreach ($integrity_results['missing_files'] as $file) {
                $report['issues'][] = array(
                    'type' => 'missing',
                    'severity' => 'high',
                    'file' => $file,
                    'description' => 'Core file is missing'
                );
            }
        }

        // Process unknown files
        if (!empty($integrity_results['unknown_files'])) {
            foreach ($integrity_results['unknown_files'] as $file) {
                $report['issues'][] = array(
                    'type' => 'unknown',
                    'severity' => 'medium',
                    'file' => $file['file'],
                    'description' => 'Unknown file found in WordPress root',
                    'details' => $file
                );
            }
        }

        // Add recommendations
        if (!empty($report['issues'])) {
            $report['recommendations'] = array(
                'Backup your website before making any changes',
                'Download clean WordPress files from wordpress.org',
                'Replace modified core files with clean versions',
                'Remove unknown files after verifying they are not needed',
                'Change all passwords (WordPress admin, FTP, hosting)',
                'Update all plugins and themes to latest versions',
                'Run a malware scan using security plugins'
            );
        }

        return $report;
    }
}
