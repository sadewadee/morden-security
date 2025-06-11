<?php
if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap ms-blocked-ips-wrap">
    <h1 class="ms-page-title">
        <span class="ms-page-icon">🚫</span>
        <?php _e('Blocked IP Addresses', 'morden-security'); ?>
    </h1>

    <div class="ms-blocked-ips-actions">
        <button type="button" id="ms-add-ip-manually" class="button button-primary">
            <?php _e('Block IP Manually', 'morden-security'); ?>
        </button>
        <button type="button" id="ms-import-ip-list" class="button button-secondary">
            <?php _e('Import IP List', 'morden-security'); ?>
        </button>
        <button type="button" id="ms-export-blocked-ips" class="button button-secondary">
            <?php _e('Export Blocked IPs', 'morden-security'); ?>
        </button>
    </div>

    <div id="ms-blocked-ips-container" class="ms-blocked-ips-container">
        <table id="ms-blocked-ips-table" class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php _e('IP Address', 'morden-security'); ?></th>
                    <th><?php _e('Country', 'morden-security'); ?></th>
                    <th><?php _e('Reason', 'morden-security'); ?></th>
                    <th><?php _e('Blocked Until', 'morden-security'); ?></th>
                    <th><?php _e('Type', 'morden-security'); ?></th>
                    <th><?php _e('Created', 'morden-security'); ?></th>
                    <th><?php _e('Actions', 'morden-security'); ?></th>
                </tr>
            </thead>
            <tbody id="ms-blocked-ips-tbody">
                <tr>
                    <td colspan="7"><?php _e('Loading blocked IPs...', 'morden-security'); ?></td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<div id="ms-manual-block-modal" class="ms-modal" style="display: none;">
    <div class="ms-modal-content">
        <div class="ms-modal-header">
            <h3><?php _e('Block IP Address Manually', 'morden-security'); ?></h3>
            <span class="ms-modal-close">&times;</span>
        </div>
        <div class="ms-modal-body">
            <form id="ms-manual-block-form">
                <div class="ms-form-group">
                    <label for="manual-ip-address"><?php _e('IP Address:', 'morden-security'); ?></label>
                    <input type="text" id="manual-ip-address" name="ip_address" placeholder="192.168.1.100" required />
                </div>
                <div class="ms-form-group">
                    <label for="manual-block-reason"><?php _e('Reason:', 'morden-security'); ?></label>
                    <textarea id="manual-block-reason" name="reason" rows="3" placeholder="<?php _e('Enter reason for blocking this IP...', 'morden-security'); ?>" required></textarea>
                </div>
                <div class="ms-form-group">
                    <label for="manual-block-type"><?php _e('Block Type:', 'morden-security'); ?></label>
                    <select id="manual-block-type" name="block_type">
                        <option value="temporary"><?php _e('Temporary (1 hour)', 'morden-security'); ?></option>
                        <option value="permanent"><?php _e('Permanent', 'morden-security'); ?></option>
                    </select>
                </div>
                <div class="ms-form-actions">
                    <button type="submit" class="button button-primary"><?php _e('Block IP', 'morden-security'); ?></button>
                    <button type="button" class="button ms-modal-close"><?php _e('Cancel', 'morden-security'); ?></button>
                </div>
            </form>
        </div>
    </div>
</div>
