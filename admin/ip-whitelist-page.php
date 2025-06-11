<?php
if (!defined('ABSPATH')) {
    exit;
}

$options = get_option('ms_settings', array());
?>

<div class="wrap ms-whitelist-wrap">
    <h1 class="ms-page-title">
        <span class="ms-page-icon">✅</span>
        <?php _e('IP Whitelist Management', 'morden-security'); ?>
    </h1>

    <form method="post" action="options.php" class="ms-whitelist-form">
        <?php settings_fields('ms_settings_group'); ?>

        <div class="ms-whitelist-sections">
            <div class="ms-whitelist-section">
                <h2><?php _e('Admin IP Addresses', 'morden-security'); ?></h2>
                <p class="description"><?php _e('IP addresses that should never be blocked. Your current IP will be auto-added when you login.', 'morden-security'); ?></p>
                <textarea name="ms_settings[admin_whitelist_ips]" rows="8" cols="50" class="large-text" placeholder="192.168.1.100&#10;203.0.113.0"><?php echo esc_textarea($options['admin_whitelist_ips'] ?? ''); ?></textarea>
            </div>

            <div class="ms-whitelist-section">
                <h2><?php _e('Custom Whitelist IPs', 'morden-security'); ?></h2>
                <p class="description"><?php _e('Additional IP addresses or ranges to whitelist. Supports CIDR notation (192.168.1.0/24) and wildcards (10.0.0.*).', 'morden-security'); ?></p>
                <textarea name="ms_settings[custom_whitelist_ips]" rows="8" cols="50" class="large-text" placeholder="192.168.1.0/24&#10;10.0.0.*"><?php echo esc_textarea($options['custom_whitelist_ips'] ?? ''); ?></textarea>
            </div>

            <div class="ms-whitelist-section">
                <h2><?php _e('Current Information', 'morden-security'); ?></h2>
                <div class="ms-current-info">
                    <p><strong><?php _e('Your Current IP:', 'morden-security'); ?></strong> <code><?php echo esc_html(MS_Core::get_instance()->ms_get_user_ip()); ?></code></p>
                    <p><strong><?php _e('Server IP:', 'morden-security'); ?></strong> <code><?php echo esc_html($_SERVER['SERVER_ADDR'] ?? 'Unknown'); ?></code></p>
                </div>
            </div>

            <div class="ms-whitelist-section">
                <h2><?php _e('Currently Logged In Users', 'morden-security'); ?></h2>
                <div id="ms-logged-in-users">
                    <?php
                    $logged_in_users = get_transient('ms_logged_in_users');
                    if ($logged_in_users && !empty($logged_in_users)) {
                        echo '<table class="wp-list-table widefat fixed striped">';
                        echo '<thead><tr><th>User</th><th>IP Address</th><th>Login Time</th><th>Role</th></tr></thead>';
                        echo '<tbody>';
                        foreach ($logged_in_users as $user_id => $data) {
                            $user = get_user_by('ID', $user_id);
                            if ($user) {
                                echo '<tr>';
                                echo '<td>' . esc_html($user->user_login) . '</td>';
                                echo '<td><code>' . esc_html($data['ip']) . '</code></td>';
                                echo '<td>' . esc_html(date('Y-m-d H:i:s', $data['timestamp'])) . '</td>';
                                echo '<td>' . esc_html($data['user_role'] ?? 'Unknown') . '</td>';
                                echo '</tr>';
                            }
                        }
                        echo '</tbody></table>';
                    } else {
                        echo '<p>' . __('No users currently tracked.', 'morden-security') . '</p>';
                    }
                    ?>
                </div>
            </div>
        </div>

        <?php submit_button(__('Save Whitelist Settings', 'morden-security'), 'primary'); ?>
    </form>
</div>
