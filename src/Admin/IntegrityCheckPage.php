<?php

namespace MordenSecurity\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use MordenSecurity\Modules\Scanner\Integrity;
use MordenSecurity\Modules\Scanner\Scheduler;
use MordenSecurity\Modules\Scanner\Quarantine;
use MordenSecurity\Core\LoggerSQLite;

class IntegrityCheckPage
{
    private Integrity $integrity;
    private Quarantine $quarantine;

    public function __construct()
    {
        $logger = new LoggerSQLite();
        $this->quarantine = new Quarantine();
        $this->integrity = new Integrity($logger, $this->quarantine);

        add_action('admin_init', [$this, 'registerSettings']);
        add_action('wp_ajax_ms_start_integrity_scan', [$this, 'handle_start_scan']);
        add_action('wp_ajax_ms_get_scan_status', [$this, 'handle_get_scan_status']);
        add_action('wp_ajax_ms_get_scan_results', [$this, 'handle_get_scan_results']);
        add_action('wp_ajax_ms_quarantine_file', [$this, 'handle_quarantine_file']);
        add_action('wp_ajax_ms_restore_file', [$this, 'handle_restore_file']);
        add_action('wp_ajax_ms_delete_quarantined_file', [$this, 'handle_delete_quarantined_file']);
        add_action('wp_ajax_ms_get_file_diff', [$this, 'handle_get_file_diff']);
        add_action('wp_ajax_ms_repair_core_file', [$this, 'handle_repair_core_file']);

        add_action('ms_run_integrity_scan_event', [$this->integrity, 'runScan']);
        add_action(Scheduler::CRON_HOOK, [Scheduler::class, 'handleScheduledScan']);
        add_action('update_option_ms_scanner_schedule', [$this, 'handle_schedule_update'], 10, 2);
    }

    public function handle_schedule_update($old_value, $value): void
    {
        $enabled = $value['scan_enabled'] ?? false;
        $frequency = $value['scan_frequency'] ?? 'daily';

        if ($enabled) {
            Scheduler::schedule($frequency);
        } else {
            Scheduler::unschedule();
        }
    }

    public function handle_start_scan(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        // Schedule a one-off event to run the scan in the background.
        wp_schedule_single_event(time(), 'ms_run_integrity_scan_event');

        wp_send_json_success(['message' => 'Scan process initiated. It will run in the background.']);
    }

    public function handle_get_scan_status(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $status = $this->integrity->getScanStatus();
        wp_send_json_success($status);
    }

    public function handle_get_scan_results(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $results = $this->integrity->getScanResults();
        wp_send_json_success($results);
    }

    public function handle_quarantine_file(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $file_path = sanitize_text_field($_POST['file_path'] ?? '');
        if (empty($file_path)) {
            wp_send_json_error(['message' => 'Invalid file path.'], 400);
        }

        $success = $this->quarantine->quarantineFile($file_path);

        if ($success) {
            wp_send_json_success(['message' => 'File quarantined successfully.']);
        } else {
            wp_send_json_error(['message' => 'Failed to quarantine file.']);
        }
    }

    public function handle_restore_file(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $file_name = sanitize_file_name($_POST['file_name'] ?? '');
        $original_path = sanitize_text_field($_POST['original_path'] ?? ''); // This needs to be stored somewhere

        // For now, we can't reliably restore without knowing the original path.
        // This is a placeholder for a more advanced implementation.
        wp_send_json_error(['message' => 'Restore functionality not fully implemented yet. Original path is unknown.'], 501);
    }

    public function handle_delete_quarantined_file(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $file_name = sanitize_file_name($_POST['file_name'] ?? '');
        if (empty($file_name)) {
            wp_send_json_error(['message' => 'Invalid file name.'], 400);
        }

        $success = $this->quarantine->deleteQuarantinedFile($file_name);

        if ($success) {
            wp_send_json_success(['message' => 'File deleted successfully.']);
        } else {
            wp_send_json_error(['message' => 'Failed to delete file.']);
        }
    }

    public function handle_repair_core_file(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $file_path = sanitize_text_field($_POST['file_path'] ?? '');
        if (empty($file_path)) {
            wp_send_json_error(['message' => 'Invalid file path.'], 400);
        }

        $success = $this->integrity->repairCoreFile($file_path);

        if ($success) {
            wp_send_json_success(['message' => 'File repaired successfully.']);
        } else {
            wp_send_json_error(['message' => 'Failed to repair file.']);
        }
    }

    public function handle_get_file_diff(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $file_path = sanitize_text_field($_POST['file_path'] ?? '');
        if (empty($file_path)) {
            wp_send_json_error(['message' => 'Invalid file path.'], 400);
        }

        $diff = $this->integrity->getFileDiff($file_path);

        if ($diff === null) {
            wp_send_json_error(['message' => 'Could not retrieve file diff.']);
        } else {
            wp_send_json_success(['diff' => $diff]);
        }
    }

    public function render(): void
    {
        ?>
        <div class="wrap ms-integrity-check-page">
            <h1><?php _e('Security Scanner', 'morden-security'); ?></h1>

            <h2 class="nav-tab-wrapper">
                <a href="#scanner" class="nav-tab nav-tab-active"><?php _e('Security Scanner', 'morden-security'); ?></a>
                <a href="#settings" class="nav-tab"><?php _e('Settings', 'morden-security'); ?></a>
                <a href="#scheduling" class="nav-tab"><?php _e('Scheduling', 'morden-security'); ?></a>
                <a href="#cleanup" class="nav-tab"><?php _e('Cleaning Up', 'morden-security'); ?></a>
                <a href="#quarantine" class="nav-tab"><?php _e('Quarantine', 'morden-security'); ?></a>
            </h2>

            <div id="scanner" class="tab-content active">
                <?php $this->renderScannerTab(); ?>
            </div>
            <div id="settings" class="tab-content">
                <?php $this->renderSettingsTab(); ?>
            </div>
            <div id="scheduling" class="tab-content">
                <?php $this->renderSchedulingTab(); ?>
            </div>
            <div id="cleanup" class="tab-content">
                <p>Cleanup options will go here.</p>
            </div>
            <div id="quarantine" class="tab-content">
                <?php $this->renderQuarantineTab(); ?>
            </div>
        </div>
        <?php
    }

    private function renderScannerTab(): void
    {
        $status = get_transient('ms_scan_progress');
        $is_running = ($status && isset($status['status']) && $status['status'] === 'running');
        $is_finished = ($status && isset($status['status']) && $status['status'] === 'finished');
        ?>
        <div class="ms-scanner-main">
            <div class="ms-scan-summary">
                <!-- This section will be populated by JS -->
                <div class="ms-summary-item">
                    <span class="label"><?php _e('Started', 'morden-security'); ?></span>
                    <span class="value" id="ms-scan-started">-</span>
                </div>
                <div class="ms-summary-item">
                    <span class="label"><?php _e('Finished', 'morden-security'); ?></span>
                    <span class="value" id="ms-scan-finished">-</span>
                </div>
                <div class="ms-summary-item">
                    <span class="label"><?php _e('Duration', 'morden-security'); ?></span>
                    <span class="value" id="ms-scan-duration">-</span>
                </div>
                <div class="ms-summary-item">
                    <span class="label"><?php _e('Checksum mismatch', 'morden-security'); ?></span>
                    <span class="value" id="ms-stat-checksum">0</span>
                </div>
                <div class="ms-summary-item">
                    <span class="label"><?php _e('Unattended files', 'morden-security'); ?></span>
                    <span class="value" id="ms-stat-unattended">0</span>
                </div>
                <div class="ms-summary-item">
                    <span class="label"><?php _e('Changed files', 'morden-security'); ?></span>
                    <span class="value" id="ms-stat-changed">0</span>
                </div>
                 <div class="ms-summary-item">
                    <span class="label"><?php _e('New files', 'morden-security'); ?></span>
                    <span class="value" id="ms-stat-new">0</span>
                </div>
            </div>

            <div class="ms-scan-status">
                <div class="ms-scan-progress">
                    <span id="ms-scan-progress-text">0 / 0</span>
                    <small><?php _e('Scanned / Files to scan', 'morden-security'); ?></small>
                </div>
                <div class="ms-scan-issues">
                     <span id="ms-scan-issues-text">0</span>
                    <small><?php _e('Issues found', 'morden-security'); ?></small>
                </div>
            </div>

            <div id="ms-progress-bar" style="<?php echo $is_running ? '' : 'display: none;'; ?>">
                <div id="ms-progress-bar-inner"></div>
                <span id="ms-progress-percentage">0%</span>
            </div>

            <div class="ms-scan-results-summary">
                <?php if ($is_running) : ?>
                    <p><?php _e('Scan is currently in progress...', 'morden-security'); ?></p>
                <?php elseif ($is_finished) : ?>
                    <p><?php _e('Previous scan finished. Loading results...', 'morden-security'); ?></p>
                <?php else : ?>
                    <p><?php _e('This website has never been scanned. To start scanning click the button below.', 'morden-security'); ?></p>
                <?php endif; ?>
            </div>

             <div class="ms-scan-controls" style="<?php echo $is_running ? 'display: none;' : ''; ?>">
                <button class="button" id="ms-start-quick-scan"><?php _e('Start Quick Scan', 'morden-security'); ?></button>
                <button class="button button-primary" id="ms-start-full-scan"><?php _e('Start Full Scan', 'morden-security'); ?></button>
            </div>
        </div>
        <?php
    }

    private function renderQuarantineTab(): void
    {
        $quarantined_files = $this->quarantine->getQuarantinedFiles();
        ?>
        <h3><?php _e('Quarantined Files', 'morden-security'); ?></h3>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php _e('File Name', 'morden-security'); ?></th>
                    <th><?php _e('Size', 'morden-security'); ?></th>
                    <th><?php _e('Date Quarantined', 'morden-security'); ?></th>
                    <th><?php _e('Actions', 'morden-security'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($quarantined_files)) : ?>
                    <tr>
                        <td colspan="4"><?php _e('No files in quarantine.', 'morden-security'); ?></td>
                    </tr>
                <?php else : ?>
                    <?php foreach ($quarantined_files as $file) : ?>
                        <tr>
                            <td><code><?php echo esc_html($file['file_name']); ?></code></td>
                            <td><?php echo esc_html(size_format($file['size'])); ?></td>
                            <td><?php echo esc_html(date('Y-m-d H:i:s', $file['date'])); ?></td>
                            <td>
                                <button class="button button-small ms-restore-file" data-file="<?php echo esc_attr($file['file_name']); ?>"><?php _e('Restore', 'morden-security'); ?></button>
                                <button class="button button-small button-danger ms-delete-quarantined-file" data-file="<?php echo esc_attr($file['file_name']); ?>"><?php _e('Delete Permanently', 'morden-security'); ?></button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
        <?php
    }

    private function renderSettingsTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php
            settings_fields('ms_scanner_settings_group');
            do_settings_sections('morden-security-scanner-settings');
            submit_button();
            ?>
        </form>
        <?php
    }

    private function renderSchedulingTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php
            settings_fields('ms_scanner_schedule_group');
            do_settings_sections('morden-security-scanner-schedule');
            submit_button();
            ?>
        </form>
        <?php
    }

    public function registerSettings(): void
    {
        // Settings Tab
        register_setting('ms_scanner_settings_group', 'ms_scanner_settings');
        add_settings_section('ms_scanner_general_section', __('Scanner Settings', 'morden-security'), null, 'morden-security-scanner-settings');
        add_settings_field('ms_scan_for_new_files', __('Scan for new files', 'morden-security'), [$this, 'renderSelectField'], 'morden-security-scanner-settings', 'ms_scanner_general_section', [
            'group' => 'ms_scanner_settings',
            'name' => 'scan_for_new_files',
            'options' => ['executable' => __('Executable files', 'morden-security'), 'all' => __('All files', 'morden-security')]
        ]);
        add_settings_field('ms_unwanted_file_extensions', __('Unwanted file extensions', 'morden-security'), [$this, 'renderTextField'], 'morden-security-scanner-settings', 'ms_scanner_general_section', [
            'group' => 'ms_scanner_settings',
            'name' => 'unwanted_file_extensions',
            'description' => __('Specify file extensions to search for. Use comma to separate items.', 'morden-security')
        ]);
        add_settings_field('ms_directories_to_exclude', __('Directories to exclude', 'morden-security'), [$this, 'renderTextareaField'], 'morden-security-scanner-settings', 'ms_scanner_general_section', [
            'group' => 'ms_scanner_settings',
            'name' => 'directories_to_exclude',
            'description' => __('Specify directories to exclude from scanning. One directory per line.', 'morden-security')
        ]);

        // Scheduling Tab
        register_setting('ms_scanner_schedule_group', 'ms_scanner_schedule');
        add_settings_section('ms_scanner_schedule_section', __('Automated Recurring Scan Schedule', 'morden-security'), null, 'morden-security-scanner-schedule');
        add_settings_field('ms_schedule_scan_enabled', __('Launch Full Scan', 'morden-security'), [$this, 'renderToggleField'], 'morden-security-scanner-schedule', 'ms_scanner_schedule_section', [
            'group' => 'ms_scanner_schedule',
            'name' => 'scan_enabled'
        ]);
        add_settings_field('ms_schedule_scan_frequency', __('Frequency', 'morden-security'), [$this, 'renderSelectField'], 'morden-security-scanner-schedule', 'ms_scanner_schedule_section', [
            'group' => 'ms_scanner_schedule',
            'name' => 'scan_frequency',
            'options' => ['daily' => __('Once a day', 'morden-security'), 'weekly' => __('Once a week', 'morden-security')]
        ]);
    }

    public function renderSelectField(array $args): void
    {
        $settings = get_option($args['group']);
        $name = esc_attr($args['name']);
        $value = $settings[$name] ?? '';
        ?>
        <select name="<?php echo esc_attr($args['group']); ?>[<?php echo $name; ?>]">
            <?php foreach ($args['options'] as $key => $label) : ?>
                <option value="<?php echo esc_attr($key); ?>" <?php selected($value, $key); ?>>
                    <?php echo esc_html($label); ?>
                </option>
            <?php endforeach; ?>
        </select>
        <?php
    }

    public function renderTextField(array $args): void
    {
        $settings = get_option($args['group']);
        $name = esc_attr($args['name']);
        $value = $settings[$name] ?? '';
        ?>
        <input type="text" name="<?php echo esc_attr($args['group']); ?>[<?php echo $name; ?>]" value="<?php echo esc_attr($value); ?>" class="regular-text">
        <p class="description"><?php echo esc_html($args['description']); ?></p>
        <?php
    }

    public function renderTextareaField(array $args): void
    {
        $settings = get_option($args['group']);
        $name = esc_attr($args['name']);
        $value = $settings[$name] ?? '';
        ?>
        <textarea name="<?php echo esc_attr($args['group']); ?>[<?php echo $name; ?>]" rows="5" class="large-text"><?php echo esc_textarea($value); ?></textarea>
        <p class="description"><?php echo esc_html($args['description']); ?></p>
        <?php
    }

    public function renderToggleField(array $args): void
    {
        $settings = get_option($args['group']);
        $name = esc_attr($args['name']);
        $value = $settings[$name] ?? '';
        ?>
        <label class="ms-switch">
            <input type="checkbox" name="<?php echo esc_attr($args['group']); ?>[<?php echo $name; ?>]" value="1" <?php checked($value, '1'); ?>>
            <span class="ms-slider round"></span>
        </label>
        <?php
    }
}
