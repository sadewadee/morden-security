<?php

namespace MordenSecurity\Modules\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Modules\Scanner\Quarantine;

class Integrity
{
    private const CORE_CHECKSUMS_URL = 'https://api.wordpress.org/core/checksums/1.0/';

    private const STATUS_OK = 1;
    private const STATUS_MODIFIED = 15;
    private const STATUS_UNABLE_TO_PROCESS = 13;
    private const STATUS_MALICIOUS = 17;
    private const STATUS_EXTRA = 18;
    private const STATUS_MISSING = 19;
    private const STATUS_NON_PUBLIC = 20;
    private const STATUS_NO_CHECKSUMS = 21;
    private const STATUS_UNWANTED_EXTENSION = 22;
    private const STATUS_FILE_CHANGED = 23;

    private LoggerSQLite $logger;
    private Quarantine $quarantine;
    private array $malware_signatures = [];

    public function __construct(LoggerSQLite $logger, Quarantine $quarantine)
    {
        $this->logger = $logger;
        $this->quarantine = $quarantine;
        $this->loadMalwareSignatures();
    }

    private function loadMalwareSignatures(): void
    {
        $signatures_path = MS_PLUGIN_PATH . 'data/malware-signatures.json';
        if (file_exists($signatures_path)) {
            $signatures_json = file_get_contents($signatures_path);
            $signatures_data = json_decode($signatures_json, true);
            if (isset($signatures_data['signatures'])) {
                $this->malware_signatures = $signatures_data['signatures'];
            }
        }
    }

    public function startScan(): void
    {
        wp_schedule_single_event(time(), 'ms_run_integrity_scan_event');
    }

    public function getScanStatus(): array
    {
        return get_transient('ms_scan_progress') ?: ['status' => 'idle'];
    }

    public function runScan(): void
    {
        set_transient('ms_scan_progress', ['status' => 'running', 'progress' => 0, 'issues' => 0, 'total_files' => 0, 'scanned_files' => 0], HOUR_IN_SECONDS);

        $scan_id = $this->logger->startNewScan();
        $total_issues = 0;
        $summary = [];

        $core_issues = $this->verifyCoreFiles($scan_id);
        $total_issues += $core_issues;
        $summary['core'] = ['name' => 'WordPress Core', 'issues' => $core_issues, 'status' => $core_issues > 0 ? 'issues_found' : 'verified'];

        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $plugins = get_plugins();
        foreach ($plugins as $plugin_file => $plugin_data) {
            $slug = dirname($plugin_file);
            $plugin_issues = $this->verifyPluginFiles($scan_id, $slug, $plugin_file);
            $total_issues += $plugin_issues;
            $summary['plugins'][$slug] = ['name' => $plugin_data['Name'], 'issues' => $plugin_issues, 'status' => $plugin_issues > 0 ? 'issues_found' : 'verified'];
        }

        $themes = wp_get_themes();
        foreach ($themes as $theme_slug => $theme_data) {
            if ($theme_data->parent()) {
                continue;
            }
            $theme_issues = $this->verifyThemeFiles($scan_id, $theme_slug);
            $total_issues += $theme_issues;
            $summary['themes'][$theme_slug] = ['name' => $theme_data->get('Name'), 'issues' => $theme_issues, 'status' => $theme_issues > 0 ? 'issues_found' : 'verified'];
        }

        $this->logger->finishScan($scan_id, $total_issues, $summary);

        set_transient('ms_scan_progress', ['status' => 'finished'], HOUR_IN_SECONDS);
    }

    public function getScanResults(): array
    {
        return $this->logger->getLatestScanResults();
    }

    private function getCoreChecksums(): ?array
    {
        global $wp_version;
        $locale = get_locale();
        $url = self::CORE_CHECKSUMS_URL . '?version=' . $wp_version . '&locale=' . $locale;
        $response = wp_remote_get($url);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        return $data['checksums'] ?? null;
    }

    public function verifyCoreFiles(int $scan_id): int
    {
        $issues_found = 0;
        $official_checksums = $this->getCoreChecksums();

        if ($official_checksums === null) {
            $this->logger->logScanIssue($scan_id, [
                'file_path' => 'WordPress API',
                'issue_type' => 'API_FETCH_FAILED',
                'details' => 'Could not fetch checksums from WordPress.org.'
            ]);
            return 1;
        }

        if (empty($official_checksums)) {
            $this->logger->logScanIssue($scan_id, [
                'file_path' => 'WordPress API',
                'issue_type' => 'INVALID_API_RESPONSE',
                'details' => 'Checksum list from WordPress.org was empty or invalid.'
            ]);
            return 1;
        }

        $local_files = $this->getWordPressFiles();
        $settings = get_option('ms_scanner_settings', []);
        $unwanted_extensions_raw = $settings['unwanted_file_extensions'] ?? '';
        $unwanted_extensions = array_filter(array_map('trim', explode(',', $unwanted_extensions_raw)));

        $total_files = count($local_files);
        $scanned_files = 0;

        foreach ($local_files as $relative_path => $full_path) {
            $scanned_files++;
            $file_extension = pathinfo($full_path, PATHINFO_EXTENSION);

            if (!empty($unwanted_extensions) && in_array($file_extension, $unwanted_extensions)) {
                $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'UNWANTED_EXTENSION']);
                $issues_found++;
            }

            $file_content = file_get_contents($full_path);
            foreach ($this->malware_signatures as $signature) {
                if (preg_match($signature['pattern'], $file_content)) {
                    $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'MALWARE_DETECTED', 'details' => $signature['name']]);
                    $issues_found++;
                    break;
                }
            }

            $current_hash = md5_file($full_path);
            $current_size = filesize($full_path);
            $current_mod_time = filemtime($full_path);
            $previous_metadata = $this->logger->getFileMetadata($relative_path);

            if ($previous_metadata) {
                if ($previous_metadata['file_hash'] !== $current_hash || $previous_metadata['file_size'] !== $current_size) {
                    $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'FILE_CHANGED']);
                    $issues_found++;
                }
            }
            $this->logger->updateFileMetadata($relative_path, $current_hash, $current_size, $current_mod_time);

            if (isset($official_checksums[$relative_path])) {
                if ($current_hash !== $official_checksums[$relative_path]) {
                    $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'CORE_FILE_MODIFIED']);
                    $issues_found++;
                }
                unset($official_checksums[$relative_path]);
            } else {
                // Allow known exceptions that are not part of the official checksums
                $known_exceptions = ['wp-config.php', '.htaccess', 'robots.txt'];
                if (!in_array($relative_path, $known_exceptions)) {
                    $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'CORE_EXTRA_FILE']);
                    $issues_found++;
                }
            }

            if ($scanned_files % 10 === 0) { // Update progress every 10 files
                set_transient('ms_scan_progress', [
                    'status' => 'running',
                    'progress' => round(($scanned_files / $total_files) * 100),
                    'issues' => $issues_found,
                    'total_files' => $total_files,
                    'scanned_files' => $scanned_files
                ], HOUR_IN_SECONDS);
            }
        }

        foreach (array_keys($official_checksums) as $missing_file) {
            $this->logger->logScanIssue($scan_id, ['file_path' => $missing_file, 'issue_type' => 'CORE_FILE_MISSING']);
            $issues_found++;
        }

        return $issues_found;
    }

    private function getWordPressFiles(): array
    {
        $settings = get_option('ms_scanner_settings', []);
        // Provide sensible defaults for directories to exclude from core scan.
        $excluded_dirs_raw = $settings['directories_to_exclude'] ?? "wp-content\n.git\n.svn";
        $excluded_dirs = array_filter(array_map('trim', explode("\n", $excluded_dirs_raw)));
        $excluded_paths = [];
        foreach ($excluded_dirs as $dir) {
            $excluded_paths[] = trailingslashit(ABSPATH) . $dir;
        }

        $files = [];
        $path = ABSPATH;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS | \RecursiveDirectoryIterator::FOLLOW_SYMLINKS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            $is_excluded = false;
            foreach ($excluded_paths as $excluded_path) {
                if (strpos($file->getRealPath(), $excluded_path) === 0) {
                    $is_excluded = true;
                    break;
                }
            }

            if (!$is_excluded && $file->isFile()) {
                $relative_path = str_replace(ABSPATH, '', $file->getRealPath());
                $files[$relative_path] = $file->getRealPath();
            }
        }
        return $files;
    }

    public function verifyPluginFiles(int $scan_id, string $plugin_slug, string $plugin_file): int
    {
        $issues_found = 0;
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file);
        $version = $plugin_data['Version'];

        $url = "https://downloads.wordpress.org/plugin-checksums/{$plugin_slug}/{$version}.json";
        $response = wp_remote_get($url);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            $this->logger->logScanIssue($scan_id, ['file_path' => $plugin_slug, 'issue_type' => 'NOT_PUBLIC_PLUGIN', 'details' => 'This may be a premium or custom plugin not listed on WordPress.org.']);
            return 1;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        $official_checksums = $data['files'] ?? [];

        if (empty($official_checksums)) {
            $this->logger->logScanIssue($scan_id, ['file_path' => $plugin_slug, 'issue_type' => 'NO_INTEGRITY_DATA', 'details' => 'No checksums available for this version.']);
            return 1;
        }

        $plugin_dir = WP_PLUGIN_DIR . '/' . dirname($plugin_file);
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($plugin_dir, \RecursiveDirectoryIterator::SKIP_DOTS));

        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            $relative_path = str_replace($plugin_dir . '/', '', $file->getRealPath());
            if (isset($official_checksums[$relative_path])) {
                if (md5_file($file->getRealPath()) !== $official_checksums[$relative_path]) {
                    $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'PLUGIN_FILE_MODIFIED']);
                    $issues_found++;
                }
                unset($official_checksums[$relative_path]);
            } else {
                $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'PLUGIN_EXTRA_FILE']);
                $issues_found++;
            }
        }

        foreach (array_keys($official_checksums) as $missing_file) {
            $this->logger->logScanIssue($scan_id, ['file_path' => $missing_file, 'issue_type' => 'PLUGIN_FILE_MISSING']);
            $issues_found++;
        }

        return $issues_found;
    }

    public function verifyThemeFiles(int $scan_id, string $theme_slug): int
    {
        $issues_found = 0;
        $theme = wp_get_theme($theme_slug);
        $version = $theme->get('Version');

        $url = "https://downloads.wordpress.org/theme-checksums/{$theme_slug}/{$version}.json";
        $response = wp_remote_get($url);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            $this->logger->logScanIssue($scan_id, ['file_path' => $theme_slug, 'issue_type' => 'NOT_PUBLIC_THEME', 'details' => 'This may be a premium or custom theme not listed on WordPress.org.']);
            return 1;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        $official_checksums = $data['files'] ?? [];

        if (empty($official_checksums)) {
            $this->logger->logScanIssue($scan_id, ['file_path' => $theme_slug, 'issue_type' => 'NO_INTEGRITY_DATA', 'details' => 'No checksums available for this version.']);
            return 1;
        }

        $theme_dir = $theme->get_stylesheet_directory();
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($theme_dir, \RecursiveDirectoryIterator::SKIP_DOTS));

        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            $relative_path = str_replace($theme_dir . '/', '', $file->getRealPath());
            if (isset($official_checksums[$relative_path])) {
                if (md5_file($file->getRealPath()) !== $official_checksums[$relative_path]) {
                    $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'THEME_FILE_MODIFIED']);
                    $issues_found++;
                }
                unset($official_checksums[$relative_path]);
            } else {
                $this->logger->logScanIssue($scan_id, ['file_path' => $relative_path, 'issue_type' => 'THEME_EXTRA_FILE']);
                $issues_found++;
            }
        }

        foreach (array_keys($official_checksums) as $missing_file) {
            $this->logger->logScanIssue($scan_id, ['file_path' => $missing_file, 'issue_type' => 'THEME_FILE_MISSING']);
            $issues_found++;
        }

        return $issues_found;
    }

    public function repairCoreFile(string $relative_path): bool
    {
        global $wp_version;

        $official_checksums = $this->getCoreChecksums();
        if (!$official_checksums || !isset($official_checksums[$relative_path])) {
            $this->logger->logSecurityEvent(['event_type' => 'file_repair_failed', 'severity' => 2, 'message' => 'Could not get official checksum for file.', 'context' => ['file' => $relative_path]]);
            return false;
        }
        $official_md5 = $official_checksums[$relative_path];

        if (!$this->quarantine->quarantineFile($relative_path)) {
            $this->logger->logSecurityEvent(['event_type' => 'file_repair_failed', 'severity' => 2, 'message' => 'Failed to quarantine file.', 'context' => ['file' => $relative_path]]);
            return false;
        }

        $url = "https://core.svn.wordpress.org/tags/{$wp_version}/{$relative_path}";
        $response = wp_remote_get($url);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            $this->quarantine->restoreFile($relative_path);
            return false;
        }

        $official_content = wp_remote_retrieve_body($response);

        if (md5($official_content) !== $official_md5) {
            $this->quarantine->restoreFile($relative_path);
            $this->logger->logSecurityEvent(['event_type' => 'file_repair_failed', 'severity' => 3, 'message' => 'Downloaded file hash does not match official checksum.', 'context' => ['file' => $relative_path]]);
            return false;
        }

        $local_file_path = ABSPATH . $relative_path;
        if (file_put_contents($local_file_path, $official_content) === false) {
            $this->quarantine->restoreFile($relative_path);
            return false;
        }

        if (md5_file($local_file_path) !== $official_md5) {
            unlink($local_file_path);
            $this->quarantine->restoreFile($relative_path);
            $this->logger->logSecurityEvent(['event_type' => 'file_repair_failed', 'severity' => 3, 'message' => 'Restored file hash does not match official checksum.', 'context' => ['file' => $relative_path]]);
            return false;
        }

        $this->logger->logSecurityEvent([
            'event_type' => 'file_repair_success',
            'severity' => 1,
            'message' => sprintf('Core file repaired and verified successfully: %s', $relative_path),
            'context' => ['file' => $relative_path, 'source' => 'wordpress.org']
        ]);

        return true;
    }

    public function getFileDiff(string $relative_path): ?string
    {
        global $wp_version;
        $local_file_path = ABSPATH . $relative_path;

        if (!file_exists($local_file_path)) {
            return null;
        }

        $url = "https://core.svn.wordpress.org/tags/{$wp_version}/{$relative_path}";
        $response = wp_remote_get($url);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $official_content = wp_remote_retrieve_body($response);
        $local_content = file_get_contents($local_file_path);

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/template.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/screen.php';

        $diff = wp_text_diff($official_content, $local_content, [
            'title' => sprintf('Differences between official and local versions of %s', $relative_path),
            'title_left' => 'Official Version',
            'title_right' => 'Your Version',
        ]);

        return $diff;
    }
}
