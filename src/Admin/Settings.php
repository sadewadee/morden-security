<?php

namespace MordenSecurity\Admin;

if (!defined('ABSPATH')) {
    exit;
}

class Settings
{
    public function __construct()
    {
        add_action('admin_init', [$this, 'initializeSettings']);
    }

    public function render(): void
    {
        $activeTab = sanitize_key($_GET['tab'] ?? 'general');

        ?>
        <div class="wrap">
            <h1><?php _e('Morden Security Settings', 'morden-security'); ?></h1>

            <nav class="nav-tab-wrapper">
                <a href="?page=morden-security-settings&tab=general"
                   class="nav-tab <?php echo $activeTab === 'general' ? 'nav-tab-active' : ''; ">
                    <?php _e('General', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=firewall"
                   class="nav-tab <?php echo $activeTab === 'firewall' ? 'nav-tab-active' : ''; ">
                    <?php _e('Firewall', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=bots"
                   class="nav-tab <?php echo $activeTab === 'bots' ? 'nav-tab-active' : ''; ">
                    <?php _e('Bot Protection', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=ip"
                   class="nav-tab <?php echo $activeTab === 'ip' ? 'nav-tab-active' : ''; ">
                    <?php _e('IP Management', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=countries"
                   class="nav-tab <?php echo $activeTab === 'countries' ? 'nav-tab-active' : ''; ">
                    <?php _e('Country Blocking', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=login"
                   class="nav-tab <?php echo $activeTab === 'login' ? 'nav-tab-active' : ''; ">
                    <?php _e('Login Protection', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=performance"
                   class="nav-tab <?php echo $activeTab === 'performance' ? 'nav-tab-active' : ''; ">
                    <?php _e('Performance', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=advanced"
                   class="nav-tab <?php echo $activeTab === 'advanced' ? 'nav-tab-active' : ''; ">
                    <?php _e('Advanced', 'morden-security'); ?>
                </a>
            </nav>

            <div class="tab-content">
                <?php
                switch ($activeTab) {
                    case 'general':
                        $this->renderGeneralTab();
                        break;
                    case 'firewall':
                        $this->renderFirewallTab();
                        break;
                    case 'bots':
                        $this->renderBotsTab();
                        break;
                    case 'ip':
                        $this->renderIPTab();
                        break;
                    case 'countries':
                        $this->renderCountriesTab();
                        break;
                    case 'login':
                        $this->renderLoginTab();
                        break;
                    case 'performance':
                        $this->renderPerformanceTab();
                        break;
                    case 'advanced':
                        $this->renderAdvancedTab();
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    public function initializeSettings(): void
    {
        register_setting('morden-security-general', 'ms_security_enabled');
        register_setting('morden-security-general', 'ms_logging_enabled');
        register_setting('morden-security-general', 'ms_log_retention_days');
        register_setting('morden-security-general', 'ms_notification_email');

        register_setting('morden-security-firewall', 'ms_firewall_enabled');
        register_setting('morden-security-firewall', 'ms_waf_sensitivity');
        register_setting('morden-security-firewall', 'ms_owasp_rules_enabled');
        register_setting('morden-security-firewall', 'ms_custom_rules_enabled');

        register_setting('morden-security-bots', 'ms_bot_detection_enabled');
        register_setting('morden-security-bots', 'ms_bot_sensitivity');
        register_setting('morden-security-bots', 'ms_good_bot_whitelist');
        register_setting('morden-security-bots', 'ms_bot_challenge_threshold');
        register_setting('morden-security-bots', 'ms_bot_block_threshold');

        register_setting('morden-security-ip', 'ms_auto_ip_blocking');
        register_setting('morden-security-ip', 'ms_default_block_duration');
        register_setting('morden-security-ip', 'ms_threat_score_threshold');
        register_setting('morden-security-ip', 'ms_escalation_enabled');
        register_setting('morden-security-ip', 'ms_whitelist_admin_enabled');

        register_setting('morden-security-countries', 'ms_country_blocking_enabled');
        register_setting('morden-security-countries', 'ms_blocked_countries');
        register_setting('morden-security-countries', 'ms_allowed_countries');
        register_setting('morden-security-countries', 'ms_country_detection_method');

        register_setting('morden-security-login', 'ms_login_protection_enabled');
        register_setting('morden-security-login', 'ms_max_login_attempts');
        register_setting('morden-security-login', 'ms_lockout_duration');
        register_setting('morden-security-login', 'ms_strong_password_required');
        register_setting('morden-security-login', 'ms_captcha_enabled');

        register_setting('morden-security-performance', 'ms_cache_enabled');
        register_setting('morden-security-performance', 'ms_cache_duration');
        register_setting('morden-security-performance', 'ms_database_optimization');

        register_setting('morden-security-advanced', 'ms_debug_mode');
        register_setting('morden-security-advanced', 'ms_maintenance_mode');
        register_setting('morden-security-advanced', 'ms_webhook_enabled');
        register_setting('morden-security-advanced', 'ms_api_access_enabled');
        register_setting('morden-security-advanced', 'ms_delete_data_on_uninstall');
    }

    private function renderGeneralTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-general'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Enable Security Protection', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_security_enabled" value="1"
                               <?php checked(get_option('ms_security_enabled', true)); ?> />
                        <p class="description"><?php _e('Master switch for all security features', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Enable Security Logging', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_logging_enabled" value="1"
                               <?php checked(get_option('ms_logging_enabled', true)); ?> />
                        <p class="description"><?php _e('Log all security events to database', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Log Retention (Days)', 'morden-security'); ?></th>
                    <td>
                        <input type="number" name="ms_log_retention_days" min="1" max="365"
                               value="<?php echo esc_attr(get_option('ms_log_retention_days', 30)); ?>" />
                        <p class="description"><?php _e('Number of days to keep security logs', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Notification Email', 'morden-security'); ?></th>
                    <td>
                        <input type="email" name="ms_notification_email"
                               value="<?php echo esc_attr(get_option('ms_notification_email', get_option('admin_email'))); ?>" />
                        <p class="description"><?php _e('Email address for security alerts', 'morden-security'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    private function renderFirewallTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-firewall'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Enable Web Application Firewall', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_firewall_enabled" value="1"
                               <?php checked(get_option('ms_firewall_enabled', true)); ?> />
                        <p class="description"><?php _e('Enable WAF protection against common attacks', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('WAF Sensitivity Level', 'morden-security'); ?></th>
                    <td>
                        <select name="ms_waf_sensitivity">
                            <option value="low" <?php selected(get_option('ms_waf_sensitivity', 'medium'), 'low'); ?>>
                                <?php _e('Low (Permissive)', 'morden-security'); ?>
                            </option>
                            <option value="medium" <?php selected(get_option('ms_waf_sensitivity', 'medium'), 'medium'); ?>>
                                <?php _e('Medium (Balanced)', 'morden-security'); ?>
                            </option>
                            <option value="high" <?php selected(get_option('ms_waf_sensitivity', 'medium'), 'high'); ?>>
                                <?php _e('High (Strict)', 'morden-security'); ?>
                            </option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Enable OWASP Core Rules', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_owasp_rules_enabled" value="1"
                               <?php checked(get_option('ms_owasp_rules_enabled', true)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Enable Custom Rules', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_custom_rules_enabled" value="1"
                               <?php checked(get_option('ms_custom_rules_enabled', true)); ?> />
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    private function renderBotsTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-bots'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Enable Bot Detection', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_bot_detection_enabled" value="1"
                               <?php checked(get_option('ms_bot_detection_enabled', true)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Bot Detection Sensitivity', 'morden-security'); ?></th>
                    <td>
                        <select name="ms_bot_sensitivity">
                            <option value="low" <?php selected(get_option('ms_bot_sensitivity', 'medium'), 'low'); ?>>
                                <?php _e('Low', 'morden-security'); ?>
                            </option>
                            <option value="medium" <?php selected(get_option('ms_bot_sensitivity', 'medium'), 'medium'); ?>>
                                <?php _e('Medium', 'morden-security'); ?>
                            </option>
                            <option value="high" <?php selected(get_option('ms_bot_sensitivity', 'medium'), 'high'); ?>>
                                <?php _e('High', 'morden-security'); ?>
                            </option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Whitelist Good Bots', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_good_bot_whitelist" value="1"
                               <?php checked(get_option('ms_good_bot_whitelist', true)); ?> />
                        <p class="description"><?php _e('Allow search engine and legitimate bots', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Bot Challenge Threshold', 'morden-security'); ?></th>
                    <td>
                        <input type="number" name="ms_bot_challenge_threshold" min="1" max="100"
                               value="<?php echo esc_attr(get_option('ms_bot_challenge_threshold', 70)); ?>" />
                        <p class="description"><?php _e('Bot score threshold for challenge (1-100)', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Bot Block Threshold', 'morden-security'); ?></th>
                    <td>
                        <input type="number" name="ms_bot_block_threshold" min="1" max="100"
                               value="<?php echo esc_attr(get_option('ms_bot_block_threshold', 90)); ?>" />
                        <p class="description"><?php _e('Bot score threshold for blocking (1-100)', 'morden-security'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    private function renderIPTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-ip'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Enable Auto IP Blocking', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_auto_ip_blocking" value="1"
                               <?php checked(get_option('ms_auto_ip_blocking', true)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Default Block Duration', 'morden-security'); ?></th>
                    <td>
                        <select name="ms_default_block_duration">
                            <option value="3600" <?php selected(get_option('ms_default_block_duration', '3600'), '3600'); ?>>
                                <?php _e('1 Hour', 'morden-security'); ?>
                            </option>
                            <option value="21600" <?php selected(get_option('ms_default_block_duration', '3600'), '21600'); ?>>
                                <?php _e('6 Hours', 'morden-security'); ?>
                            </option>
                            <option value="86400" <?php selected(get_option('ms_default_block_duration', '3600'), '86400'); ?>>
                                <?php _e('24 Hours', 'morden-security'); ?>
                            </option>
                            <option value="permanent" <?php selected(get_option('ms_default_block_duration', '3600'), 'permanent'); ?>>
                                <?php _e('Permanent', 'morden-security'); ?>
                            </option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Threat Score Threshold', 'morden-security'); ?></th>
                    <td>
                        <input type="number" name="ms_threat_score_threshold" min="1" max="100"
                               value="<?php echo esc_attr(get_option('ms_threat_score_threshold', 50)); ?>" />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Enable Escalation', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_escalation_enabled" value="1"
                               <?php checked(get_option('ms_escalation_enabled', true)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Auto-Whitelist Admins', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_whitelist_admin_enabled" value="1"
                               <?php checked(get_option('ms_whitelist_admin_enabled', true)); ?> />
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    private function renderCountriesTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-countries'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Enable Country Blocking', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_country_blocking_enabled" value="1"
                               <?php checked(get_option('ms_country_blocking_enabled', false)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Blocked Countries', 'morden-security'); ?></th>
                    <td>
                        <textarea name="ms_blocked_countries" rows="5" cols="50" placeholder="CN&#10;RU&#10;IR"><?php
                            $blockedCountries = get_option('ms_blocked_countries', []);
                            if (is_array($blockedCountries)) {
                                $blockedCountries = implode("\n", $blockedCountries);
                            }
                            echo esc_textarea($blockedCountries);
                        ?></textarea>
                        <p class="description"><?php _e('Enter country codes, one per line (e.g., CN, RU)', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Country Detection Method', 'morden-security'); ?></th>
                    <td>
                        <select name="ms_country_detection_method">
                            <option value="headers" <?php selected(get_option('ms_country_detection_method', 'headers'), 'headers'); ?>>
                                <?php _e('Server Headers', 'morden-security'); ?>
                            </option>
                            <option value="ip_lookup" <?php selected(get_option('ms_country_detection_method', 'headers'), 'ip_lookup'); ?>>
                                <?php _e('IP Lookup', 'morden-security'); ?>
                            </option>
                        </select>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    private function renderLoginTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-login'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Enable Login Protection', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_login_protection_enabled" value="1"
                               <?php checked(get_option('ms_login_protection_enabled', true)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Max Login Attempts', 'morden-security'); ?></th>
                    <td>
                        <input type="number" name="ms_max_login_attempts" min="1" max="20"
                               value="<?php echo esc_attr(get_option('ms_max_login_attempts', 5)); ?>" />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Lockout Duration (minutes)', 'morden-security'); ?></th>
                    <td>
                        <input type="number" name="ms_lockout_duration" min="1" max="1440"
                               value="<?php echo esc_attr(get_option('ms_lockout_duration', 30)); ?>" />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Require Strong Passwords', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_strong_password_required" value="1"
                               <?php checked(get_option('ms_strong_password_required', false)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Enable CAPTCHA', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_captcha_enabled" value="1"
                               <?php checked(get_option('ms_captcha_enabled', false)); ?> />
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    private function renderPerformanceTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-performance'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Enable Security Cache', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_cache_enabled" value="1"
                               <?php checked(get_option('ms_cache_enabled', true)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Cache Duration (minutes)', 'morden-security'); ?></th>
                    <td>
                        <input type="number" name="ms_cache_duration" min="1" max="1440"
                               value="<?php echo esc_attr(get_option('ms_cache_duration', 15)); ?>" />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Database Optimization', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_database_optimization" value="1"
                               <?php checked(get_option('ms_database_optimization', true)); ?> />
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    private function renderAdvancedTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-advanced'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Debug Mode', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_debug_mode" value="1"
                               <?php checked(get_option('ms_debug_mode', false)); ?> />
                        <p class="description"><?php _e('Enable detailed logging for debugging', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Maintenance Mode', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_maintenance_mode" value="1"
                               <?php checked(get_option('ms_maintenance_mode', false)); ?> />
                        <p class="description"><?php _e('Block all non-admin access', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Enable Webhook Notifications', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_webhook_enabled" value="1"
                               <?php checked(get_option('ms_webhook_enabled', false)); ?> />
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Enable API Access', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_api_access_enabled" value="1"
                               <?php checked(get_option('ms_api_access_enabled', false)); ?> />
                    </td>
                </tr>
                <tr style="color: red;">
                    <th scope="row" style="color: red;"><?php _e('Remove Data on Uninstall', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_delete_data_on_uninstall" value="1"
                               <?php checked(get_option('ms_delete_data_on_uninstall'), 1); ?> />
                        <p class="description" style="color: red;"><?php _e('If checked, all Morden Security data (logs, settings, IP rules) will be permanently deleted when the plugin is uninstalled. This action cannot be undone.', 'morden-security'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }
}