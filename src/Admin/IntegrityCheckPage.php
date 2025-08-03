<?php

namespace MordenSecurity\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use MordenSecurity\Modules\Scanner\Integrity;
use MordenSecurity\Core\LoggerSQLite;

class IntegrityCheckPage
{
    private Integrity $integrity;

    public function __construct()
    {
        $logger = new LoggerSQLite();
        $this->integrity = new Integrity($logger);

        add_action('admin_init', [$this, 'registerSettings']);
        add_action('wp_ajax_ms_start_integrity_scan', [$this, 'handle_start_scan']);
        add_action('wp_ajax_ms_get_scan_status', [$this, 'handle_get_scan_status']);
        add_action('wp_ajax_ms_get_scan_results', [$this, 'handle_get_scan_results']);

        add_action('ms_run_integrity_scan_event', [$this->integrity, 'runScan']);
    }

    public function handle_start_scan(): void
    {
        check_ajax_referer('ms_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $this->integrity->startScan();
        wp_send_json_success(['message' => 'Scan started.']);
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
                <form method="post" action="options.php">
                    <?php
                    settings_fields('ms_scanner_settings_group');
                    do_settings_sections('morden-security-scanner');
                    submit_button();
                    ?>
                </form>
            </div>
            <div id="scheduling" class="tab-content">
                <p>Scheduling options will go here.</p>
            </div>
            <div id="cleanup" class="tab-content">
                <p>Cleanup options will go here.</p>
            </div>
            <div id="quarantine" class="tab-content">
                <p>Quarantine will go here.</p>
            </div>
        </div>
        <?php
    }

    private function renderScannerTab(): void
    {
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
                     <span id="ms-scan-issues-text">0 / 0</span>
                    <small><?php _e('Critical issues / Issues total', 'morden-security'); ?></small>
                </div>
            </div>

            <div class="ms-scan-results">
                <p><?php _e('It seems this website has never been scanned. To start scanning click the button below.', 'morden-security'); ?></p>
            </div>

             <div class="ms-scan-controls">
                <button class="button" id="ms-start-quick-scan"><?php _e('Start Quick Scan', 'morden-security'); ?></button>
                <button class="button button-primary" id="ms-start-full-scan"><?php _e('Start Full Scan', 'morden-security'); ?></button>
            </div>
        </div>
        <?php
    }

    public function registerSettings(): void
    {
        register_setting('ms_scanner_settings_group', 'ms_scanner_settings');

        add_settings_section(
            'ms_scanner_general_section',
            __('Scanner Settings', 'morden-security'),
            null,
            'morden-security-scanner'
        );

        add_settings_field(
            'ms_scan_for_new_files',
            __('Scan for new files', 'morden-security'),
            [$this, 'renderSelectField'],
            'morden-security-scanner',
            'ms_scanner_general_section',
            [
                'name' => 'scan_for_new_files',
                'options' => [
                    'executable' => __('Executable files', 'morden-security'),
                    'all' => __('All files', 'morden-security'),
                ]
            ]
        );

        add_settings_field(
            'ms_unwanted_file_extensions',
            __('Unwanted file extensions', 'morden-security'),
            [$this, 'renderTextField'],
            'morden-security-scanner',
            'ms_scanner_general_section',
            [
                'name' => 'unwanted_file_extensions',
                'description' => __('Specify file extensions to search for. Use comma to separate items.', 'morden-security')
            ]
        );

        add_settings_field(
            'ms_directories_to_exclude',
            __('Directories to exclude', 'morden-security'),
            [$this, 'renderTextareaField'],
            'morden-security-scanner',
            'ms_scanner_general_section',
            [
                'name' => 'directories_to_exclude',
                'description' => __('Specify directories to exclude from scanning. One directory per line.', 'morden-security')
            ]
        );
    }

    public function renderSelectField(array $args): void
    {
        $settings = get_option('ms_scanner_settings');
        $name = esc_attr($args['name']);
        $value = $settings[$name] ?? '';
        ?>
        <select name="ms_scanner_settings[<?php echo $name; ?>]">
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
        $settings = get_option('ms_scanner_settings');
        $name = esc_attr($args['name']);
        $value = $settings[$name] ?? '';
        ?>
        <input type="text" name="ms_scanner_settings[<?php echo $name; ?>]" value="<?php echo esc_attr($value); ?>" class="regular-text">
        <p class="description"><?php echo esc_html($args['description']); ?></p>
        <?php
    }

    public function renderTextareaField(array $args): void
    {
        $settings = get_option('ms_scanner_settings');
        $name = esc_attr($args['name']);
        $value = $settings[$name] ?? '';
        ?>
        <textarea name="ms_scanner_settings[<?php echo $name; ?>]" rows="5" class="large-text"><?php echo esc_textarea($value); ?></textarea>
        <p class="description"><?php echo esc_html($args['description']); ?></p>
        <?php
    }
}
