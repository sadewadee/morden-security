<?php
if (!defined('ABSPATH')) {
    exit;
}

$options = get_option('ms_settings', array());
?>

<div class="wrap">
    <h1><?php _e('Morden Security Settings', 'morden-security'); ?></h1>

    <div class="ms-admin-header">
        <div class="ms-stats-grid">
            <div class="ms-stat-box">
                <h3><?php _e('Login Attempts (24h)', 'morden-security'); ?></h3>
                <span class="ms-stat-number" id="ms-login-attempts">-</span>
            </div>
            <div class="ms-stat-box">
                <h3><?php _e('Blocked IPs', 'morden-security'); ?></h3>
                <span class="ms-stat-number" id="ms-blocked-ips">-</span>
            </div>
            <div class="ms-stat-box">
                <h3><?php _e('Security Events (24h)', 'morden-security'); ?></h3>
                <span class="ms-stat-number" id="ms-security-events">-</span>
            </div>
        </div>
    </div>

    <form method="post" action="options.php">
        <?php settings_fields('ms_settings_group'); ?>

        <div class="ms-tabs">
            <nav class="nav-tab-wrapper">
                <a href="#security" class="nav-tab nav-tab-active"><?php _e('Security', 'morden-security'); ?></a>
                <a href="#login" class="nav-tab"><?php _e('Login Protection', 'morden-security'); ?></a>
                <a href="#firewall" class="nav-tab"><?php _e('Firewall', 'morden-security'); ?></a>
                <a href="#logs" class="nav-tab"><?php _e('Log Management', 'morden-security'); ?></a>
                <a href="#customization" class="nav-tab"><?php _e('Customization', 'morden-security'); ?></a>
                <a href="#turnstile" class="nav-tab"><?php _e('Cloudflare Turnstile', 'morden-security'); ?></a>
            </nav>

            <div id="security" class="tab-content active">
                <h2><?php _e('Basic Security Settings', 'morden-security'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Disable File Editor', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[disable_file_editor]" value="1" <?php checked(isset($options['disable_file_editor']) ? $options['disable_file_editor'] : 1, 1); ?> />
                                <?php _e('Disable WordPress file editor for themes and plugins', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Force SSL', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[force_ssl]" value="1" <?php checked(isset($options['force_ssl']) ? $options['force_ssl'] : 1, 1); ?> />
                                <?php _e('Force HTTPS connections on frontend', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Disable XML-RPC', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[disable_xmlrpc]" value="1" <?php checked(isset($options['disable_xmlrpc']) ? $options['disable_xmlrpc'] : 1, 1); ?> />
                                <?php _e('Disable XML-RPC to prevent brute force attacks', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Security Headers', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[enable_security_headers]" value="1" <?php checked(isset($options['enable_security_headers']) ? $options['enable_security_headers'] : 1, 1); ?> />
                                <?php _e('Add security headers to HTTP responses', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <div id="login" class="tab-content">
                <h2><?php _e('Login Protection Settings', 'morden-security'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Limit Login Attempts', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[limit_login_attempts]" value="1" <?php checked(isset($options['limit_login_attempts']) ? $options['limit_login_attempts'] : 1, 1); ?> />
                                <?php _e('Enable login attempt limiting', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Max Login Attempts', 'morden-security'); ?></th>
                        <td>
                            <input type="number" name="ms_settings[max_login_attempts]" value="<?php echo esc_attr(isset($options['max_login_attempts']) ? $options['max_login_attempts'] : 5); ?>" min="1" max="20" />
                            <p class="description"><?php _e('Maximum failed login attempts before lockout', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Lockout Duration', 'morden-security'); ?></th>
                        <td>
                            <input type="number" name="ms_settings[lockout_duration]" value="<?php echo esc_attr(isset($options['lockout_duration']) ? $options['lockout_duration'] : 1800); ?>" min="300" max="86400" />
                            <p class="description"><?php _e('Lockout duration in seconds (default: 1800 = 30 minutes)', 'morden-security'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <div id="firewall" class="tab-content">
                <h2><?php _e('Firewall Settings', 'morden-security'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Enable Firewall', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[enable_firewall]" value="1" <?php checked(isset($options['enable_firewall']) ? $options['enable_firewall'] : 1, 1); ?> />
                                <?php _e('Enable basic firewall protection', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Suspicious Requests', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[block_suspicious_requests]" value="1" <?php checked(isset($options['block_suspicious_requests']) ? $options['block_suspicious_requests'] : 1, 1); ?> />
                                <?php _e('Block requests with suspicious patterns', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Scan Uploads', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[scan_uploads]" value="1" <?php checked(isset($options['scan_uploads']) ? $options['scan_uploads'] : 1, 1); ?> />
                                <?php _e('Scan uploaded files for malicious content', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <div id="logs" class="tab-content">
                <h2><?php _e('Log Management Settings', 'morden-security'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Maximum Logs', 'morden-security'); ?></th>
                        <td>
                            <input type="number" name="ms_settings[max_logs]" value="<?php echo esc_attr(isset($options['max_logs']) ? $options['max_logs'] : 1000); ?>" min="100" max="10000" />
                            <p class="description"><?php _e('Maximum number of security logs to keep (100-10000)', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Log Retention Days', 'morden-security'); ?></th>
                        <td>
                            <input type="number" name="ms_settings[max_days_retention]" value="<?php echo esc_attr(isset($options['max_days_retention']) ? $options['max_days_retention'] : 30); ?>" min="1" max="365" />
                            <p class="description"><?php _e('Number of days to keep security logs (1-365)', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Enable Geolocation', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[enable_geolocation]" value="1" <?php checked(isset($options['enable_geolocation']) ? $options['enable_geolocation'] : 1, 1); ?> />
                                <?php _e('Enable country detection for security logs', 'morden-security'); ?>
                            </label>
                            <p class="description"><?php _e('Uses CloudFlare headers or free IP geolocation service', 'morden-security'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <div id="customization" class="tab-content">
                <h2><?php _e('WordPress Customization', 'morden-security'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Hide WordPress Version', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[hide_wp_version]" value="1" <?php checked(isset($options['hide_wp_version']) ? $options['hide_wp_version'] : 1, 1); ?> />
                                <?php _e('Hide WordPress version from HTML source', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Remove WordPress Credit', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[remove_wp_credit]" value="1" <?php checked(isset($options['remove_wp_credit']) ? $options['remove_wp_credit'] : 1, 1); ?> />
                                <?php _e('Remove WordPress credit from admin footer', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Hide WordPress Logo', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[hide_wp_logo]" value="1" <?php checked(isset($options['hide_wp_logo']) ? $options['hide_wp_logo'] : 1, 1); ?> />
                                <?php _e('Hide WordPress logo from admin bar', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Hide Admin Bar', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[hide_admin_bar]" value="1" <?php checked(isset($options['hide_admin_bar']) ? $options['hide_admin_bar'] : 1, 1); ?> />
                                <?php _e('Hide admin bar for non-administrator users', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <div id="turnstile" class="tab-content">
                <h2><?php _e('Cloudflare Turnstile Settings', 'morden-security'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Enable Turnstile', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[turnstile_enabled]" value="1" <?php checked(isset($options['turnstile_enabled']) ? $options['turnstile_enabled'] : 0, 1); ?> />
                                <?php _e('Enable Cloudflare Turnstile on login and registration forms', 'morden-security'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Site Key', 'morden-security'); ?></th>
                        <td>
                            <input type="text" name="ms_settings[turnstile_site_key]" value="<?php echo esc_attr(isset($options['turnstile_site_key']) ? $options['turnstile_site_key'] : ''); ?>" class="regular-text" />
                            <p class="description"><?php _e('Your Cloudflare Turnstile site key', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Secret Key', 'morden-security'); ?></th>
                        <td>
                            <input type="password" name="ms_settings[turnstile_secret_key]" value="<?php echo esc_attr(isset($options['turnstile_secret_key']) ? $options['turnstile_secret_key'] : ''); ?>" class="regular-text" />
                            <p class="description"><?php _e('Your Cloudflare Turnstile secret key', 'morden-security'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <?php submit_button(); ?>
    </form>
</div>
