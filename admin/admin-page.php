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
                <a href="#scan-settings" class="nav-tab"><?php _e('File Scanning', 'morden-security'); ?></a>
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
                    <tr>
                        <th scope="row"><?php _e('Block PHP in Uploads', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[block_php_uploads]" value="1" <?php checked(isset($options['block_php_uploads']) ? $options['block_php_uploads'] : 1, 1); ?> />
                                <?php _e('Forbid execution of PHP scripts in wp-content/uploads directory', 'morden-security'); ?>
                            </label>
                            <p class="description"><?php _e('Prevents malicious PHP files from being executed in the uploads folder', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Disable Pingbacks', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[disable_pingbacks]" value="1" <?php checked(isset($options['disable_pingbacks']) ? $options['disable_pingbacks'] : 1, 1); ?> />
                                <?php _e('Turn off pingbacks and trackbacks completely', 'morden-security'); ?>
                            </label>
                            <p class="description"><?php _e('Prevents spam and reduces server load from pingback requests', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Bot Protection', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[enable_bot_protection]" value="1" <?php checked(isset($options['enable_bot_protection']) ? $options['enable_bot_protection'] : 1, 1); ?> />
                                <?php _e('Enable advanced bot protection and user agent filtering', 'morden-security'); ?>
                            </label>
                            <p class="description"><?php _e('Blocks known malicious bots and suspicious user agents', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Author Scans', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[block_author_scans]" value="1" <?php checked(isset($options['block_author_scans']) ? $options['block_author_scans'] : 1, 1); ?> />
                                <?php _e('Block attempts to scan for usernames via author archives', 'morden-security'); ?>
                            </label>
                            <p class="description"><?php _e('Prevents attackers from discovering usernames through /?author=1 requests', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Database Security', 'morden-security'); ?></th>
                        <td>
                            <?php
                            global $wpdb;
                            $current_prefix = $wpdb->prefix;
                            $is_default = ($current_prefix === 'wp_');
                            ?>
                            <p><strong><?php _e('Current Database Prefix:', 'morden-security'); ?></strong> <code><?php echo esc_html($current_prefix); ?></code></p>

                            <?php if ($is_default): ?>
                                <div class="ms-warning-notice" style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin: 10px 0;">
                                    <p style="color: #856404; margin: 0;"><strong><?php _e('Warning:', 'morden-security'); ?></strong> <?php _e('You are using the default database prefix "wp_" which is insecure!', 'morden-security'); ?></p>
                                </div>

                                <label for="new_db_prefix"><?php _e('New Database Prefix:', 'morden-security'); ?></label>
                                <input type="text" id="new_db_prefix" value="" placeholder="ms_secure_" style="width: 200px;" />
                                <button type="button" id="ms-change-db-prefix" class="button button-secondary">
                                    <?php _e('Change Database Prefix', 'morden-security'); ?>
                                </button>
                                <p class="description">
                                    <?php _e('Change from default "wp_" to a custom prefix. This will update all database tables and wp-config.php file.', 'morden-security'); ?><br>
                                    <strong style="color: #d63638;"><?php _e('Warning: This action will create a backup and modify your database. Ensure you have a full backup first!', 'morden-security'); ?></strong>
                                </p>
                            <?php else: ?>
                                <p style="color: #46b450;"><strong><?php _e('✓ Good! You are using a custom database prefix.', 'morden-security'); ?></strong></p>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('File Permissions Check', 'morden-security'); ?></th>
                        <td>
                            <button type="button" id="ms-check-permissions" class="button button-secondary">
                                <?php _e('Check File Permissions', 'morden-security'); ?>
                            </button>
                            <button type="button" id="ms-fix-permissions" class="button button-primary" style="display:none;">
                                <?php _e('Fix Permissions', 'morden-security'); ?>
                            </button>
                            <p class="description"><?php _e('Scan and fix insecure file/folder permissions (777, 666)', 'morden-security'); ?></p>

                            <div id="ms-permissions-result" style="display:none; margin-top: 15px;">
                                <h4><?php _e('Permission Scan Results:', 'morden-security'); ?></h4>
                                <div id="ms-permissions-content"></div>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>


            <div id="login" class="tab-content">
                <h2><?php _e('Login Protection Settings', 'morden-security'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Hide Login URL', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[hide_login_url]" value="1" <?php checked(isset($options['hide_login_url']) ? $options['hide_login_url'] : 0, 1); ?> />
                                <?php _e('Change login URL to custom path', 'morden-security'); ?>
                            </label>
                            <br><br>
                            <label for="custom_login_url"><?php _e('Custom Login URL:', 'morden-security'); ?></label>
                            <input type="text" name="ms_settings[custom_login_url]" id="custom_login_url" value="<?php echo esc_attr($options['custom_login_url'] ?? 'secure-login'); ?>" placeholder="secure-login" style="width: 200px;" />
                            <p class="description">
                                <?php _e('Hide wp-admin and wp-login.php from bots. Your new login URL will be:', 'morden-security'); ?><br>
                                <strong><?php echo home_url('/'); ?><span id="login-url-preview"><?php echo esc_html($options['custom_login_url'] ?? 'secure-login'); ?></span></strong>
                            </p>
                        </td>
                    </tr>
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

            <div id="scan-settings" class="tab-content">
                <h2><?php _e('File Scanning & Integrity Check', 'morden-security'); ?></h2>

                <!-- Integrity Check Status -->
                <div class="ms-integrity-status-box">
                    <h3><?php _e('WordPress Integrity Status', 'morden-security'); ?></h3>
                    <?php
                    $integrity_results = get_option('ms_integrity_check_results', array());
                    $plugin_results = get_option('ms_plugin_integrity_results', array());
                    $theme_results = get_option('ms_theme_integrity_results', array());

                    if (!empty($integrity_results)) {
                        $status = $integrity_results['status'];
                        $status_class = $status === 'clean' ? 'ms-status-clean' : 'ms-status-infected';
                        $status_text = $status === 'clean' ? __('Clean', 'morden-security') : __('Issues Detected', 'morden-security');

                        echo '<div class="ms-status-indicator ' . $status_class . '">';
                        echo '<span class="ms-status-icon"></span>';
                        echo '<span class="ms-status-text">' . $status_text . '</span>';
                        echo '</div>';

                        echo '<p><strong>' . __('Last Check:', 'morden-security') . '</strong> ' . esc_html($integrity_results['last_check']) . '</p>';
                        echo '<p><strong>' . __('WordPress Version:', 'morden-security') . '</strong> ' . esc_html($integrity_results['wp_version']) . '</p>';

                        if ($status === 'infected') {
                            echo '<div class="ms-integrity-issues">';

                            if (!empty($integrity_results['modified_files'])) {
                                echo '<div class="ms-issue-section">';
                                echo '<h4>' . __('Modified Core Files:', 'morden-security') . '</h4>';
                                echo '<ul>';
                                foreach ($integrity_results['modified_files'] as $file) {
                                    echo '<li><code>' . esc_html($file) . '</code></li>';
                                }
                                echo '</ul>';
                                echo '</div>';
                            }

                            if (!empty($integrity_results['missing_files'])) {
                                echo '<div class="ms-issue-section">';
                                echo '<h4>' . __('Missing Core Files:', 'morden-security') . '</h4>';
                                echo '<ul>';
                                foreach ($integrity_results['missing_files'] as $file) {
                                    echo '<li><code>' . esc_html($file) . '</code></li>';
                                }
                                echo '</ul>';
                                echo '</div>';
                            }

                            // Manual repair instructions
                            echo '<div class="ms-repair-instructions">';
                            echo '<h4>' . __('Manual Repair Instructions', 'morden-security') . '</h4>';
                            echo '<div class="ms-repair-steps">';
                            echo '<p><strong>' . __('IMPORTANT:', 'morden-security') . '</strong> ' . __('Before proceeding, create a complete backup of your website.', 'morden-security') . '</p>';

                            echo '<h5>' . __('Step 1: Download Clean WordPress Files', 'morden-security') . '</h5>';
                            echo '<ol>';
                            echo '<li>' . sprintf(__('Download WordPress version %s from %s', 'morden-security'),
                                esc_html($integrity_results['wp_version']),
                                '<a href="https://wordpress.org/download/releases/" target="_blank">wordpress.org/download/releases/</a>') . '</li>';
                            echo '<li>' . __('Extract the downloaded ZIP file on your computer', 'morden-security') . '</li>';
                            echo '</ol>';

                            echo '<h5>' . __('Step 2: Replace Infected Core Files', 'morden-security') . '</h5>';
                            echo '<ol>';
                            echo '<li>' . __('Access your website files via FTP/SFTP or cPanel File Manager', 'morden-security') . '</li>';
                            echo '<li>' . __('Navigate to your WordPress root directory', 'morden-security') . '</li>';
                            echo '<li>' . __('Replace the following directories with clean copies:', 'morden-security') . '</li>';
                            echo '<ul>';
                            echo '<li><code>wp-admin/</code> - ' . __('Safe to replace completely', 'morden-security') . '</li>';
                            echo '<li><code>wp-includes/</code> - ' . __('Safe to replace completely', 'morden-security') . '</li>';
                            echo '</ul>';
                            echo '<li>' . __('Replace individual infected files in the root directory', 'morden-security') . '</li>';
                            echo '<li><strong>' . __('DO NOT replace:', 'morden-security') . '</strong> <code>wp-config.php</code>, <code>wp-content/</code> folder, or <code>.htaccess</code></li>';
                            echo '</ol>';

                            echo '<h5>' . __('Step 3: Verify and Test', 'morden-security') . '</h5>';
                            echo '<ol>';
                            echo '<li>' . __('Check if your website loads correctly', 'morden-security') . '</li>';
                            echo '<li>' . __('Run another integrity check using the button below', 'morden-security') . '</li>';
                            echo '<li>' . __('Change all passwords (WordPress admin, FTP, hosting)', 'morden-security') . '</li>';
                            echo '<li>' . __('Update all plugins and themes to latest versions', 'morden-security') . '</li>';
                            echo '</ol>';

                            echo '<div class="ms-warning-box">';
                            echo '<p><strong>' . __('Warning:', 'morden-security') . '</strong> ' . __('If you are not comfortable performing these steps, please contact a WordPress security professional or your hosting provider for assistance.', 'morden-security') . '</p>';
                            echo '</div>';

                            echo '</div>';
                            echo '</div>';
                            echo '</div>';
                        }
                    } else {
                        echo '<p>' . __('No integrity check has been performed yet. Click "Run Integrity Check" to scan your WordPress installation.', 'morden-security') . '</p>';
                    }
                    ?>

                    <div class="ms-integrity-actions">
                        <button type="button" id="ms-run-integrity-check" class="button button-primary">
                            <?php _e('Run Integrity Check Now', 'morden-security'); ?>
                        </button>
                        <button type="button" id="ms-view-detailed-report" class="button">
                            <?php _e('View Detailed Report', 'morden-security'); ?>
                        </button>
                    </div>
                </div>

                <!-- File Scanning Settings -->
                <h3><?php _e('File Scanning Settings', 'morden-security'); ?></h3>
                <p class="description" style="margin-bottom: 20px;">
                    <?php _e('These settings control both automatic file scanning and integrity checking. File scanning helps detect suspicious files while integrity checking verifies WordPress core files against official checksums.', 'morden-security'); ?>
                </p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Enable File Integrity Check', 'morden-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ms_settings[enable_file_integrity]" value="1" <?php checked(isset($options['enable_file_integrity']) ? $options['enable_file_integrity'] : 1, 1); ?> />
                                <?php _e('Monitor WordPress core files for unauthorized changes', 'morden-security'); ?>
                            </label>
                            <p class="description"><?php _e('Automatically checks core files daily and alerts on modifications', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Scan Sensitivity', 'morden-security'); ?></th>
                        <td>
                            <select name="ms_settings[scan_sensitivity]">
                                <option value="low" <?php selected($options['scan_sensitivity'] ?? 'medium', 'low'); ?>>
                                    <?php _e('Low (Less false positives)', 'morden-security'); ?>
                                </option>
                                <option value="medium" <?php selected($options['scan_sensitivity'] ?? 'medium', 'medium'); ?>>
                                    <?php _e('Medium (Balanced)', 'morden-security'); ?>
                                </option>
                                <option value="high" <?php selected($options['scan_sensitivity'] ?? 'medium', 'high'); ?>>
                                    <?php _e('High (More thorough)', 'morden-security'); ?>
                                </option>
                            </select>
                            <p class="description"><?php _e('Higher sensitivity may result in more false positives but better malware detection', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Max File Size to Scan', 'morden-security'); ?></th>
                        <td>
                            <input type="number" name="ms_settings[max_scan_file_size]"
                                value="<?php echo esc_attr($options['max_scan_file_size'] ?? 10); ?>"
                                min="1" max="100" /> MB
                            <p class="description"><?php _e('Files larger than this size will be skipped during scanning', 'morden-security'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Exclude Folders', 'morden-security'); ?></th>
                        <td>
                            <textarea name="ms_settings[custom_safe_folders]" rows="10" cols="50" class="large-text" placeholder="/my-plugin/&#10;/my-theme/&#10;/custom-folder/"><?php
                                echo esc_textarea($options['custom_safe_folders'] ?? '');
                            ?></textarea>
                            <p class="description">
                                <?php _e('Enter folder paths to exclude from scanning, one per line. Example: /forminator/', 'morden-security'); ?><br>
                                <?php _e('Paths are relative to wp-content/uploads/', 'morden-security'); ?><br>
                                <strong><?php _e('Default excluded folders:', 'morden-security'); ?></strong>
                                /forminator/, /contact-form-7/, /wpforms/, /elementor/, /wp-rocket/, /cache/, /backups/, /themes/
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Automatic Scanning', 'morden-security'); ?></th>
                        <td>
                            <p class="description">
                                <?php _e('File scanning and integrity checking run automatically twice daily as part of the security maintenance routine. Results are logged in the Security Logs section.', 'morden-security'); ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <!-- Detailed Report Modal -->
                <div id="ms-detailed-report-modal" class="ms-modal" style="display: none;">
                    <div class="ms-modal-content">
                        <div class="ms-modal-header">
                            <h3><?php _e('Detailed Integrity Report', 'morden-security'); ?></h3>
                            <span class="ms-modal-close">&times;</span>
                        </div>
                        <div class="ms-modal-body">
                            <div id="ms-detailed-report-content">
                                <?php _e('Loading detailed report...', 'morden-security'); ?>
                            </div>
                        </div>
                    </div>
                </div>
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