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
        <button type="button" id="ms-refresh-blocked-ips" class="button button-secondary">
            <?php _e('Refresh List', 'morden-security'); ?>
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
                <tr id="ms-loading-row">
                    <td colspan="7" class="ms-loading-cell">
                        <div class="ms-loading-spinner">
                            <span class="spinner is-active"></span>
                            <?php _e('Loading blocked IPs...', 'morden-security'); ?>
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>

        <div id="ms-no-blocked-ips" style="display: none;">
            <p><?php _e('No blocked IP addresses found.', 'morden-security'); ?></p>
        </div>

        <div id="ms-blocked-ips-error" style="display: none;">
            <div class="notice notice-error">
                <p><?php _e('Error loading blocked IPs. Please try refreshing the page.', 'morden-security'); ?></p>
            </div>
        </div>
    </div>
</div>

<!-- Manual IP Block Modal -->
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

<script type="text/javascript">
jQuery(document).ready(function($) {
    var loadingBlockedIPs = false;
    var loadTimeout;

    // Load blocked IPs on page load
    loadBlockedIPs();

    // Refresh button
    $('#ms-refresh-blocked-ips').on('click', function() {
        loadBlockedIPs();
    });

    function loadBlockedIPs() {
        if (loadingBlockedIPs) {
            console.log('Already loading blocked IPs, skipping...');
            return;
        }

        loadingBlockedIPs = true;

        // Clear any existing timeout
        if (loadTimeout) {
            clearTimeout(loadTimeout);
        }

        // Set timeout to prevent endless loading
        loadTimeout = setTimeout(function() {
            if (loadingBlockedIPs) {
                console.log('Loading timeout reached, stopping...');
                showError('Request timeout. Please try again.');
                loadingBlockedIPs = false;
            }
        }, 30000); // 30 second timeout

        // Show loading state
        showLoading();

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_get_blocked_ips',
                nonce: ms_ajax.nonce
            },
            timeout: 25000, // 25 second timeout
            success: function(response) {
                clearTimeout(loadTimeout);
                loadingBlockedIPs = false;

                if (response.success) {
                    displayBlockedIPs(response.data);
                } else {
                    showError(response.data || 'Unknown error occurred');
                }
            },
            error: function(xhr, status, error) {
                clearTimeout(loadTimeout);
                loadingBlockedIPs = false;

                console.log('AJAX Error:', status, error);
                console.log('Response:', xhr.responseText);

                var errorMessage = 'Failed to load blocked IPs.';
                if (status === 'timeout') {
                    errorMessage = 'Request timed out. Please try again.';
                } else if (xhr.status === 403) {
                    errorMessage = 'Access denied. Please refresh the page and try again.';
                } else if (xhr.status === 500) {
                    errorMessage = 'Server error. Please contact administrator.';
                }

                showError(errorMessage);
            }
        });
    }

    function showLoading() {
        $('#ms-blocked-ips-error').hide();
        $('#ms-no-blocked-ips').hide();
        $('#ms-loading-row').show();
    }

    function showError(message) {
        $('#ms-loading-row').hide();
        $('#ms-no-blocked-ips').hide();
        $('#ms-blocked-ips-error').find('p').text(message);
        $('#ms-blocked-ips-error').show();
    }

    function displayBlockedIPs(blockedIPs) {
        var tbody = $('#ms-blocked-ips-tbody');
        tbody.empty();

        if (!blockedIPs || blockedIPs.length === 0) {
            $('#ms-no-blocked-ips').show();
            return;
        }

        $.each(blockedIPs, function(index, ip) {
            var row = '<tr>';
            row += '<td><code>' + escapeHtml(ip.ip_address) + '</code></td>';
            row += '<td>' + escapeHtml(ip.country || 'Unknown') + '</td>';
            row += '<td>' + escapeHtml(ip.reason || 'No reason') + '</td>';
            row += '<td>' + (ip.blocked_until ? escapeHtml(ip.blocked_until) : 'Permanent') + '</td>';
            row += '<td>' + (ip.permanent == 1 ? 'Permanent' : 'Temporary') + '</td>';
            row += '<td>' + escapeHtml(ip.created_at) + '</td>';
            row += '<td>';
            row += '<button class="button button-small ms-unblock-ip" data-ip="' + escapeHtml(ip.ip_address) + '">';
            row += 'Unblock</button>';
            row += '</td>';
            row += '</tr>';

            tbody.append(row);
        });

        // Bind unblock events
        $('.ms-unblock-ip').on('click', function() {
            var ip = $(this).data('ip');
            var button = $(this);

            if (confirm('Are you sure you want to unblock IP: ' + ip + '?')) {
                unblockIP(ip, button);
            }
        });
    }

    function unblockIP(ip, button) {
        var originalText = button.text();
        button.prop('disabled', true).text('Unblocking...');

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_unblock_ip',
                ip: ip,
                nonce: ms_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    button.closest('tr').fadeOut(function() {
                        $(this).remove();

                        // Check if table is empty
                        if ($('#ms-blocked-ips-tbody tr').length === 0) {
                            $('#ms-no-blocked-ips').show();
                        }
                    });
                } else {
                    alert('Error: ' + response.data);
                    button.prop('disabled', false).text(originalText);
                }
            },
            error: function() {
                alert('Failed to unblock IP. Please try again.');
                button.prop('disabled', false).text(originalText);
            }
        });
    }

    function escapeHtml(text) {
        if (!text) return '';
        var map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.toString().replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    // Manual block modal
    $('#ms-add-ip-manually').on('click', function() {
        $('#ms-manual-block-modal').show();
    });

    $('.ms-modal-close').on('click', function() {
        $(this).closest('.ms-modal').hide();
    });

    $('#ms-manual-block-form').on('submit', function(e) {
        e.preventDefault();

        var formData = {
            action: 'ms_block_ip_manually',
            ip_address: $('#manual-ip-address').val(),
            reason: $('#manual-block-reason').val(),
            block_type: $('#manual-block-type').val(),
            nonce: ms_ajax.nonce
        };

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: formData,
            success: function(response) {
                if (response.success) {
                    $('#ms-manual-block-modal').hide();
                    $('#ms-manual-block-form')[0].reset();
                    loadBlockedIPs(); // Reload the list
                } else {
                    alert('Error: ' + response.data);
                }
            },
            error: function() {
                alert('Failed to block IP. Please try again.');
            }
        });
    });
});
</script>
