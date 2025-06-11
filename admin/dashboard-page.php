<?php
if (!defined('ABSPATH')) {
    exit;
}
$ms_version = class_exists('MS_Version') ? MS_Version::get_instance()->get_current_version() : MS_VERSION;
?>

<div class="wrap">
    <div class="ms-admin-header">
        <div class="ms-header-content">
            <div class="ms-logo-section">
                <div class="ms-logo">
                    <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
                        <circle cx="20" cy="20" r="18" fill="#0073aa" stroke="#fff" stroke-width="2"/>
                        <path d="M20 8L26 16H14L20 8Z" fill="#fff"/>
                        <rect x="16" y="18" width="8" height="14" fill="#fff"/>
                    </svg>
                </div>
                <div class="ms-title-section">
                    <h1 class="ms-main-title"><?php _e('Security Dashboard', 'morden-security'); ?></h1>
                    <p class="ms-subtitle"><?php _e('Monitor your WordPress security status', 'morden-security'); ?></p>
                </div>
            </div>

            <div class="ms-header-actions">
                <div class="ms-version-badge">
                    <span class="ms-version-label"><?php _e('Version', 'morden-security'); ?></span>
                    <span class="ms-version-number"><?php echo esc_html($ms_version); ?></span>
                </div>
                <div class="ms-status-indicator">
                    <span class="ms-status-dot"></span>
                    <span class="ms-status-text"><?php _e('Protection Active', 'morden-security'); ?></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Security Statistics -->
    <div class="ms-stats-grid">
        <div class="ms-stat-box">
            <div class="ms-stat-icon">🛡️</div>
            <div class="ms-stat-content">
                <h3><?php _e('Login Attempts (24h)', 'morden-security'); ?></h3>
                <span class="ms-stat-number" id="ms-login-attempts">-</span>
                <p class="ms-stat-description"><?php _e('Failed login attempts today', 'morden-security'); ?></p>
            </div>
        </div>

        <div class="ms-stat-box">
            <div class="ms-stat-icon">🚫</div>
            <div class="ms-stat-content">
                <h3><?php _e('Blocked IPs', 'morden-security'); ?></h3>
                <span class="ms-stat-number" id="ms-blocked-ips">-</span>
                <p class="ms-stat-description"><?php _e('Currently blocked IP addresses', 'morden-security'); ?></p>
            </div>
        </div>

        <div class="ms-stat-box">
            <div class="ms-stat-icon">📊</div>
            <div class="ms-stat-content">
                <h3><?php _e('Security Events (24h)', 'morden-security'); ?></h3>
                <span class="ms-stat-number" id="ms-security-events">-</span>
                <p class="ms-stat-description"><?php _e('Security events logged today', 'morden-security'); ?></p>
            </div>
        </div>

        <div class="ms-stat-box">
            <div class="ms-stat-icon">🔥</div>
            <div class="ms-stat-content">
                <h3><?php _e('Firewall Blocks (24h)', 'morden-security'); ?></h3>
                <span class="ms-stat-number" id="ms-firewall-blocks">-</span>
                <p class="ms-stat-description"><?php _e('Requests blocked by firewall', 'morden-security'); ?></p>
            </div>
        </div>
    </div>

    <!-- Quick Actions Section -->
    <div class="ms-dashboard-section">
        <h2 class="ms-section-title"><?php _e('Quick Actions', 'morden-security'); ?></h2>
        <div class="ms-actions-grid">
            <div class="ms-action-card">
                <div class="ms-action-icon">🔍</div>
                <h3><?php _e('Run Security Scan', 'morden-security'); ?></h3>
                <p><?php _e('Perform a comprehensive security scan of your WordPress installation', 'morden-security'); ?></p>
                <button type="button" id="ms-run-security-scan" class="button button-primary">
                    <?php _e('Start Scan', 'morden-security'); ?>
                </button>
            </div>

            <div class="ms-action-card">
                <div class="ms-action-icon">📁</div>
                <h3><?php _e('Check File Permissions', 'morden-security'); ?></h3>
                <p><?php _e('Scan and fix insecure file and folder permissions', 'morden-security'); ?></p>
                <a href="<?php echo admin_url('admin.php?page=ms-settings#scan-settings'); ?>" class="button button-secondary">
                    <?php _e('Check Now', 'morden-security'); ?>
                </a>
            </div>

            <div class="ms-action-card">
                <div class="ms-action-icon">📋</div>
                <h3><?php _e('View Security Logs', 'morden-security'); ?></h3>
                <p><?php _e('Monitor security events and suspicious activities', 'morden-security'); ?></p>
                <a href="<?php echo admin_url('admin.php?page=ms-security-logs'); ?>" class="button button-secondary">
                    <?php _e('View Logs', 'morden-security'); ?>
                </a>
            </div>

            <div class="ms-action-card">
                <div class="ms-action-icon">⚙️</div>
                <h3><?php _e('Security Settings', 'morden-security'); ?></h3>
                <p><?php _e('Configure security features and protection levels', 'morden-security'); ?></p>
                <a href="<?php echo admin_url('admin.php?page=ms-settings'); ?>" class="button button-secondary">
                    <?php _e('Configure', 'morden-security'); ?>
                </a>
            </div>
        </div>
    </div>

    <!-- Recent Security Events -->
    <div class="ms-dashboard-section">
        <h2 class="ms-section-title"><?php _e('Recent Security Events', 'morden-security'); ?></h2>
        <div class="ms-events-container">
            <div id="ms-recent-events-list">
                <div class="ms-loading"><?php _e('Loading recent events...', 'morden-security'); ?></div>
            </div>
        </div>
    </div>

    <!-- Security Status Overview -->
    <div class="ms-dashboard-section">
        <h2 class="ms-section-title"><?php _e('Security Status Overview', 'morden-security'); ?></h2>
        <div class="ms-overview-grid">
            <div class="ms-overview-card">
                <div class="ms-overview-header">
                    <h3><?php _e('Core Security', 'morden-security'); ?></h3>
                    <div class="ms-status-badge ms-status-good" id="ms-core-status">
                        <?php _e('Good', 'morden-security'); ?>
                    </div>
                </div>
                <div class="ms-overview-content">
                    <ul id="ms-core-features">
                        <li class="ms-feature-enabled">
                            <span class="ms-feature-icon">✅</span>
                            <?php _e('File Editor Disabled', 'morden-security'); ?>
                        </li>
                        <li class="ms-feature-enabled">
                            <span class="ms-feature-icon">✅</span>
                            <?php _e('SSL Enforced', 'morden-security'); ?>
                        </li>
                        <li class="ms-feature-enabled">
                            <span class="ms-feature-icon">✅</span>
                            <?php _e('XML-RPC Disabled', 'morden-security'); ?>
                        </li>
                    </ul>
                </div>
            </div>

            <div class="ms-overview-card">
                <div class="ms-overview-header">
                    <h3><?php _e('Firewall Protection', 'morden-security'); ?></h3>
                    <div class="ms-status-badge ms-status-good" id="ms-firewall-status">
                        <?php _e('Active', 'morden-security'); ?>
                    </div>
                </div>
                <div class="ms-overview-content">
                    <ul id="ms-firewall-features">
                        <li class="ms-feature-enabled">
                            <span class="ms-feature-icon">✅</span>
                            <?php _e('Advance Firewall Active', 'morden-security'); ?>
                        </li>
                        <li class="ms-feature-enabled">
                            <span class="ms-feature-icon">✅</span>
                            <?php _e('Bot Protection Enabled', 'morden-security'); ?>
                        </li>
                    </ul>
                </div>
            </div>

            <div class="ms-overview-card">
                <div class="ms-overview-header">
                    <h3><?php _e('Login Security', 'morden-security'); ?></h3>
                    <div class="ms-status-badge ms-status-good" id="ms-login-status">
                        <?php _e('Protected', 'morden-security'); ?>
                    </div>
                </div>
                <div class="ms-overview-content">
                    <ul id="ms-login-features">
                        <li class="ms-feature-enabled">
                            <span class="ms-feature-icon">✅</span>
                            <?php _e('Brute Force Protection', 'morden-security'); ?>
                        </li>
                        <li class="ms-feature-enabled">
                            <span class="ms-feature-icon">✅</span>
                            <?php _e('Login Attempts Limited', 'morden-security'); ?>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
    // Load dashboard stats
    loadDashboardStats();
    loadRecentEvents();

    // Refresh stats every 30 seconds
    setInterval(loadDashboardStats, 30000);

    function loadDashboardStats() {
        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_get_security_stats',
                nonce: ms_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    $('#ms-login-attempts').text(response.data.login_attempts || 0);
                    $('#ms-blocked-ips').text(response.data.blocked_ips || 0);
                    $('#ms-security-events').text(response.data.security_events || 0);
                    $('#ms-firewall-blocks').text(response.data.firewall_blocks || 0);
                }
            }
        });
    }

    function loadRecentEvents() {
        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_get_security_logs',
                limit: 10,
                nonce: ms_ajax.nonce
            },
            success: function(response) {
                if (response.success && response.data.logs) {
                    displayRecentEvents(response.data.logs);
                }
            }
        });
    }

    function displayRecentEvents(events) {
        var html = '';
        if (events.length > 0) {
            events.forEach(function(event) {
                var severityClass = 'ms-event-' + event.severity;
                html += '<div class="ms-event-item ' + severityClass + '">';
                html += '<div class="ms-event-time">' + event.created_at + '</div>';
                html += '<div class="ms-event-type">' + event.event_type + '</div>';
                html += '<div class="ms-event-ip">' + event.ip_address + '</div>';
                html += '</div>';
            });
        } else {
            html = '<div class="ms-no-events">No recent security events</div>';
        }

        $('#ms-recent-events-list').html(html);
    }

    // Security scan action
    $('#ms-run-security-scan').on('click', function() {
        var button = $(this);
        button.prop('disabled', true).text('Scanning...');

        // Redirect to integrity check
        window.location.href = '<?php echo admin_url('admin.php?page=ms-settings#scan-settings'); ?>';
    });
});
</script>