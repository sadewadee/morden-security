<?php
if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap ms-logs-wrap">
    <h1 class="ms-page-title">
        <span class="ms-page-icon">📊</span>
        <?php _e('Security Logs', 'morden-security'); ?>
    </h1>

    <div class="ms-logs-filters">
        <form method="get" class="ms-filter-form">
            <input type="hidden" name="page" value="ms-security-logs" />

            <div class="ms-filter-group">
                <label for="ms-severity-filter"><?php _e('Severity:', 'morden-security'); ?></label>
                <select name="severity" id="ms-severity-filter">
                    <option value=""><?php _e('All Severities', 'morden-security'); ?></option>
                    <option value="low"><?php _e('Low', 'morden-security'); ?></option>
                    <option value="medium"><?php _e('Medium', 'morden-security'); ?></option>
                    <option value="high"><?php _e('High', 'morden-security'); ?></option>
                    <option value="critical"><?php _e('Critical', 'morden-security'); ?></option>
                </select>
            </div>

            <div class="ms-filter-group">
                <label for="ms-days-filter"><?php _e('Time Period:', 'morden-security'); ?></label>
                <select name="days" id="ms-days-filter">
                    <option value="1"><?php _e('Last 24 hours', 'morden-security'); ?></option>
                    <option value="7" selected><?php _e('Last 7 days', 'morden-security'); ?></option>
                    <option value="30"><?php _e('Last 30 days', 'morden-security'); ?></option>
                    <option value="90"><?php _e('Last 90 days', 'morden-security'); ?></option>
                </select>
            </div>

            <div class="ms-filter-group">
                <label for="ms-limit-filter"><?php _e('Show:', 'morden-security'); ?></label>
                <select name="limit" id="ms-limit-filter">
                    <option value="50">50 <?php _e('entries', 'morden-security'); ?></option>
                    <option value="100" selected>100 <?php _e('entries', 'morden-security'); ?></option>
                    <option value="250">250 <?php _e('entries', 'morden-security'); ?></option>
                    <option value="500">500 <?php _e('entries', 'morden-security'); ?></option>
                </select>
            </div>

            <div class="ms-filter-actions">
                <button type="button" id="ms-filter-logs" class="button button-primary">
                    <?php _e('Filter Logs', 'morden-security'); ?>
                </button>
                <button type="button" id="ms-export-logs" class="button button-secondary">
                    <?php _e('Export CSV', 'morden-security'); ?>
                </button>
            </div>
        </form>
    </div>

    <div id="ms-logs-container" class="ms-logs-container">
        <table id="ms-logs-table" class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php _e('Date/Time', 'morden-security'); ?></th>
                    <th><?php _e('Event Type', 'morden-security'); ?></th>
                    <th><?php _e('IP Address', 'morden-security'); ?></th>
                    <th><?php _e('Country', 'morden-security'); ?></th>
                    <th><?php _e('Path', 'morden-security'); ?></th>
                    <th><?php _e('Description', 'morden-security'); ?></th>
                    <th><?php _e('Severity', 'morden-security'); ?></th>
                    <th><?php _e('Actions', 'morden-security'); ?></th>
                </tr>
            </thead>
            <tbody id="ms-logs-tbody">
                <tr>
                    <td colspan="8"><?php _e('Loading security logs...', 'morden-security'); ?></td>
                </tr>
            </tbody>
        </table>

        <div id="ms-logs-pagination" class="ms-pagination"></div>
    </div>
</div>
