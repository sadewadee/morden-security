<?php

namespace MordenSecurity\Modules\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

use MordenSecurity\Core\LoggerSQLite;

class Integrity
{
    private const CORE_CHECKSUMS_URL = 'https://api.wordpress.org/core/checksums/1.0/';
    private LoggerSQLite $logger;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
    }

    public function startScan(): void
    {
        // Set a transient to indicate a scan is in progress
        set_transient('ms_scan_in_progress', 'true', HOUR_IN_SECONDS);
        update_option('ms_scan_status', 'Starting core file verification...');
        update_option('ms_scan_progress', 0);

        // Schedule a one-off event to run the scan in the background
        wp_schedule_single_event(time(), 'ms_run_integrity_scan_event');
    }

    public function runScan(): void
    {
        $issues = $this->verifyCoreFiles();
        // In the future, you can add plugin and theme verification here
        // $issues = array_merge($issues, $this->verifyAllPluginFiles());
        // $issues = array_merge($issues, $this->verifyAllThemeFiles());

        // Store results
        update_option('ms_scan_last_results', $issues);
        update_option('ms_scan_status', 'Scan complete.');
        update_option('ms_scan_progress', 100);
        update_option('ms_scan_issues_found', count($issues));
        update_option('ms_scan_finished_time', time());


        // Clear the in-progress transient
        delete_transient('ms_scan_in_progress');
    }

    public function getScanStatus(): array
    {
        return [
            'status' => get_option('ms_scan_status', 'Idle'),
            'progress' => (int) get_option('ms_scan_progress', 0),
            'total_files' => (int) get_option('ms_scan_total_files', 0),
            'files_scanned' => (int) get_option('ms_scan_files_scanned', 0),
            'issues_found' => (int) get_option('ms_scan_issues_found', 0),
        ];
    }

    public function getScanResults(): array
    {
        return get_option('ms_scan_last_results', []);
    }

    public function verifyCoreFiles(): array
    {
        global $wp_version;
        $issues = [];

        update_option('ms_scan_status', 'Fetching core checksums from WordPress.org...');
        update_option('ms_scan_progress', 10);

        $url = self::CORE_CHECKSUMS_URL . '?version=' . $wp_version;
        $response = wp_remote_get($url);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            $issues[] = [
                'file_path' => 'WordPress API',
                'issue_type' => 'API_FETCH_FAILED',
                'details' => 'Could not fetch checksums from WordPress.org.'
            ];
            return $issues;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        $official_checksums = $data['checksums'] ?? [];

        if (empty($official_checksums)) {
            $issues[] = [
                'file_path' => 'WordPress API',
                'issue_type' => 'INVALID_API_RESPONSE',
                'details' => 'Checksum list from WordPress.org was empty or invalid.'
            ];
            return $issues;
        }

        update_option('ms_scan_status', 'Scanning core files...');
        update_option('ms_scan_progress', 30);

        $local_files = $this->getWordPressFiles();
        $settings = get_option('ms_scanner_settings');
        $unwanted_extensions_raw = $settings['unwanted_file_extensions'] ?? '';
        $unwanted_extensions = array_filter(array_map('trim', explode(',', $unwanted_extensions_raw)));

        $total_files = count($local_files);
        update_option('ms_scan_total_files', $total_files);
        $scanned_files = 0;

        foreach ($local_files as $file_path => $full_path) {
            $scanned_files++;
            update_option('ms_scan_files_scanned', $scanned_files);
            $progress = 30 + (int)(($scanned_files / $total_files) * 60);
            update_option('ms_scan_progress', $progress);

            $relative_path = str_replace(ABSPATH, '', $full_path);
            $file_extension = pathinfo($full_path, PATHINFO_EXTENSION);

            // Check for unwanted extensions
            if (!empty($unwanted_extensions) && in_array($file_extension, $unwanted_extensions)) {
                $issues[] = [
                    'file_path' => $relative_path,
                    'issue_type' => 'UNWANTED_EXTENSION',
                ];
            }

            if (isset($official_checksums[$relative_path])) {
                $local_hash = md5_file($full_path);
                if ($local_hash !== $official_checksums[$relative_path]) {
                    $issues[] = [
                        'file_path' => $relative_path,
                        'issue_type' => 'CORE_FILE_MODIFIED',
                    ];
                }
                // Remove from official list to track missing files
                unset($official_checksums[$relative_path]);
            } else {
                // This is an extra file not in the core distribution
                $issues[] = [
                    'file_path' => $relative_path,
                    'issue_type' => 'CORE_EXTRA_FILE',
                ];
            }
        }

        // Any remaining files in the official list are missing locally
        foreach (array_keys($official_checksums) as $missing_file) {
            $issues[] = [
                'file_path' => $missing_file,
                'issue_type' => 'CORE_FILE_MISSING',
            ];
        }

        update_option('ms_scan_progress', 95);
        return $issues;
    }

    private function getWordPressFiles(): array
    {
        $settings = get_option('ms_scanner_settings');
        $excluded_dirs_raw = $settings['directories_to_exclude'] ?? '';
        $excluded_dirs = array_filter(array_map('trim', explode("\n", $excluded_dirs_raw)));
        $excluded_paths = [];
        foreach ($excluded_dirs as $dir) {
            $excluded_paths[] = trailingslashit(ABSPATH) . $dir;
        }

        $files = [];
        $path = ABSPATH;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            // Check if the file is in an excluded directory
            $is_excluded = false;
            foreach ($excluded_paths as $excluded_path) {
                if (strpos($file->getRealPath(), $excluded_path) === 0) {
                    $is_excluded = true;
                    break;
                }
            }

            if (!$is_excluded && $file->isFile()) {
                $files[$file->getBasename()] = $file->getRealPath();
            }
        }
        return $files;
    }

    public function verifyPluginFiles(string $plugin): array
    {
        // Logic to verify plugin files
        return [];
    }

    public function verifyThemeFiles(string $theme): array
    {
        // Logic to verify theme files
        return [];
    }
}
