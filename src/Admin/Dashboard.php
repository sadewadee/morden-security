<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\SecurityCore;
use MordenSecurity\Modules\IPManagement\IPBlocker;
use MordenSecurity\Utils\IPUtils;
use MordenSecurity\Core\SecurityEventTypes;

class Dashboard {
    private $logger;
    private $securityCore;
    private $ipBlocker;

    public function __construct(LoggerSQLite $logger, SecurityCore $securityCore) {
        $this->logger = $logger;
        $this->securityCore = $securityCore;
        $this->ipBlocker = new IPBlocker($logger);
        add_action('admin_init', [$this, 'initializeSettings']);
    }

    public function render(): void {
        $this->handleFormSubmission();

        $stats = $this->getStatistics();
        $recentEvents = $this->logger->getRecentEvents(50);
        $securityStatus = $this->securityCore->getSecurityStatus();
        $blockedIPs = $this->getBlockedIPs();
        $whitelistedIPs = $this->getWhitelistedIPs();
        $activeTab = sanitize_key($_GET['tab'] ?? 'general');

        ?>
        <div class="wrap ms-dashboard">
            <h1><?php _e('Morden Security Dashboard', 'morden-security'); ?></h1>

            <div class="nav-tab-wrapper">
                <a href="#dashboard" class="nav-tab nav-tab-active"><?php _e('Dashboard', 'morden-security'); ?></a>
                <a href="#activities" class="nav-tab"><?php _e('Activities', 'morden-security'); ?></a>
                <a href="#session" class="nav-tab"><?php _e('Session', 'morden-security'); ?></a>
                <a href="#lockout" class="nav-tab"><?php _e('Lockout', 'morden-security'); ?></a>
                <a href="#settings" class="nav-tab"><?php _e('Settings', 'morden-security'); ?></a>
                <a href="#access-list" class="nav-tab"><?php _e('Access List', 'morden-security'); ?></a>
                <a href="#hardening" class="nav-tab"><?php _e('Hardening', 'morden-security'); ?></a>
            </div>

            <div id="dashboard" class="tab-content active">
                <!-- Mobile-friendly alert for threat level -->
                <div class="ms-threat-level-card ms-threat-<?php echo esc_attr($securityStatus['threat_level']); ?>">
                    <h3><?php _e('Current Threat Level', 'morden-security'); ?></h3>
                    <div class="ms-threat-indicator">
                        <div class="ms-threat-level"><?php echo esc_html(ucfirst($securityStatus['threat_level'])); ?></div>
                        <div class="ms-threat-description">
                            <?php echo esc_html($securityStatus['description']); ?>
                        </div>
                    </div>
                </div>

                <!-- Responsive stats grid -->
                <div class="ms-stat-cards">
                    <div class="ms-stat-card blocked">
                        <div class="ms-stat-number"><?php echo number_format($stats['blocked_requests']); ?></div>
                        <div class="ms-stat-label"><?php _e('Blocked Requests', 'morden-security'); ?></div>
                    </div>

                    <div class="ms-stat-card bots">
                        <div class="ms-stat-number"><?php echo number_format($stats['bot_detections']); ?></div>
                        <div class="ms-stat-label"><?php _e('Bot Detections', 'morden-security'); ?></div>
                    </div>

                    <div class="ms-stat-card firewall">
                        <div class="ms-stat-number"><?php echo number_format($stats['firewall_blocks']); ?></div>
                        <div class="ms-stat-label"><?php _e('Firewall Blocks', 'morden-security'); ?></div>
                    </div>

                    <div class="ms-stat-card total">
                        <div class="ms-stat-number"><?php echo number_format($stats['total_events']); ?></div>
                        <div class="ms-stat-label"><?php _e('Total Events', 'morden-security'); ?></div>
                    </div>
                </div>
            </div>



            <div id="activities" class="tab-content">
                <?php $this->renderActivitiesTab($recentEvents); ?>
            </div>

            <div id="session" class="tab-content">
                <?php $this->renderActiveSessionsTab(); ?>
            </div>

            <div id="lockout" class="tab-content">
                <?php $this->renderBlockedIPsTab($blockedIPs); ?>
            </div>

            <div id="settings" class="tab-content">
                <nav class="nav-tab-wrapper">
                    <a href="#general-settings" class="nav-tab nav-tab-active"><?php _e('General', 'morden-security'); ?></a>
                    <a href="#firewall-settings" class="nav-tab"><?php _e('Firewall', 'morden-security'); ?></a>
                    <a href="#bots-settings" class="nav-tab"><?php _e('Bot Protection', 'morden-security'); ?></a>
                    <a href="#ip-settings" class="nav-tab"><?php _e('IP Management', 'morden-security'); ?></a>
                    <a href="#countries-settings" class="nav-tab"><?php _e('Country Blocking', 'morden-security'); ?></a>
                    <a href="#login-settings" class="nav-tab"><?php _e('Login Protection', 'morden-security'); ?></a>
                    <a href="#performance-settings" class="nav-tab"><?php _e('Performance', 'morden-security'); ?></a>
                    <a href="#advanced-settings" class="nav-tab"><?php _e('Advanced', 'morden-security'); ?></a>
                </nav>
                <div id="general-settings" class="tab-pane active">
                    <?php $this->renderGeneralTab(); ?>
                </div>
                <div id="firewall-settings" class="tab-pane">
                    <?php $this->renderFirewallTab(); ?>
                </div>
                <div id="bots-settings" class="tab-pane">
                    <?php $this->renderBotsTab(); ?>
                </div>
                <div id="ip-settings" class="tab-pane">
                    <?php $this->renderIPTab(); ?>
                </div>
                <div id="countries-settings" class="tab-pane">
                    <?php $this->renderCountriesTab(); ?>
                </div>
                <div id="login-settings" class="tab-pane">
                    <?php $this->renderLoginTab(); ?>
                </div>
                <div id="performance-settings" class="tab-pane">
                    <?php $this->renderPerformanceTab(); ?>
                </div>
                <div id="advanced-settings" class="tab-pane">
                    <?php $this->renderAdvancedTab(); ?>
                </div>
            </div>

            <div id="access-list" class="tab-content">
                <?php
                $this->renderWhitelistTab($whitelistedIPs);
                $this->renderAddRuleTab();
                ?>
            </div>

            <div id="hardening" class="tab-content">
                <?php $this->renderHardeningTab(); ?>
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

        register_setting('morden-security-hardening', 'ms_hide_wp_version');
        register_setting('morden-security-hardening', 'ms_disable_xmlrpc');
        register_setting('morden-security-hardening', 'ms_protect_config');
        register_setting('morden-security-hardening', 'ms_restrict_file_edit');
        register_setting('morden-security-hardening', 'ms_sanitize_headers');
        register_setting('morden-security-hardening', 'ms_disable_php_in_uploads');
        register_setting('morden-security-hardening', 'ms_disable_directory_browsing');
        register_setting('morden-security-hardening', 'ms_disable_user_enumeration');
        register_setting('morden-security-hardening', 'ms_hide_wp_file_structure');
        register_setting('morden-security-hardening', 'ms_remove_generator_meta');
        register_setting('morden-security-hardening', 'ms_disable_file_execution');
        register_setting('morden-security-hardening', 'ms_disable_rest_api');
        register_setting('morden-security-hardening', 'ms_remove_rsd_link');
        register_setting('morden-security-hardening', 'ms_disable_pingbacks');
    }

    private function renderHardeningTab(): void
    {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('morden-security-hardening'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Disable PHP Execution in Uploads Directory', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_disable_php_in_uploads" value="1"
                               <?php checked(get_option('ms_disable_php_in_uploads', true)); ?> />
                        <p class="description"><?php _e('Prevents execution of PHP scripts in the uploads directory.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Disable Built-in File Editors', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_restrict_file_edit" value="1"
                               <?php checked(get_option('ms_restrict_file_edit', true)); ?> />
                        <p class="description"><?php _e('Disables the file editor in the WordPress dashboard.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Hide WordPress Version', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_hide_wp_version" value="1"
                               <?php checked(get_option('ms_hide_wp_version', true)); ?> />
                        <p class="description"><?php _e('Removes the WordPress version number from the header.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Disable Directory Browsing', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_disable_directory_browsing" value="1"
                               <?php checked(get_option('ms_disable_directory_browsing', true)); ?> />
                        <p class="description"><?php _e('Prevents visitors from browsing your directory structure.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Disable User Enumeration', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_disable_user_enumeration" value="1"
                               <?php checked(get_option('ms_disable_user_enumeration', true)); ?> />
                        <p class="description"><?php _e('Prevents attackers from discovering usernames.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Disable XML-RPC', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_disable_xmlrpc" value="1"
                               <?php checked(get_option('ms_disable_xmlrpc', true)); ?> />
                        <p class="description"><?php _e('Disables the XML-RPC functionality, a common target for attacks.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Secure wp-config.php File', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_protect_config" value="1"
                               <?php checked(get_option('ms_protect_config', true)); ?> />
                        <p class="description"><?php _e('Adds .htaccess rules to protect your wp-config.php file.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Hide WordPress File Structure', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_hide_wp_file_structure" value="1"
                               <?php checked(get_option('ms_hide_wp_file_structure', true)); ?> />
                        <p class="description"><?php _e('Hides the default WordPress file structure from attackers.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Remove WordPress Generator Meta', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_remove_generator_meta" value="1"
                               <?php checked(get_option('ms_remove_generator_meta', true)); ?> />
                        <p class="description"><?php _e('Removes the WordPress generator meta tag.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Disable File Execution in Specific Folders', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_disable_file_execution" value="1"
                               <?php checked(get_option('ms_disable_file_execution', true)); ?> />
                        <p class="description"><?php _e('Disables direct file execution in wp-includes and wp-content.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Disable WordPress REST API', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_disable_rest_api" value="1"
                               <?php checked(get_option('ms_disable_rest_api', true)); ?> />
                        <p class="description"><?php _e('Disables the WordPress REST API for non-logged-in users.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Remove RSD Link', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_remove_rsd_link" value="1"
                               <?php checked(get_option('ms_remove_rsd_link', true)); ?> />
                        <p class="description"><?php _e('Removes the Really Simple Discovery (RSD) link from the header.', 'morden-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Disable Pingbacks', 'morden-security'); ?></th>
                    <td>
                        <input type="checkbox" name="ms_disable_pingbacks" value="1"
                               <?php checked(get_option('ms_disable_pingbacks', true)); ?> />
                        <p class="description"><?php _e('Disables pingbacks, which can be used for DDoS attacks.', 'morden-security'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
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
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    private function handleFormSubmission(): void
    {
        if (!isset($_POST['ms_ip_rule_nonce']) || !wp_verify_nonce($_POST['ms_ip_rule_nonce'], 'ms_add_ip_rule')) {
            return;
        }

        $ipAddress = sanitize_text_field($_POST['ip_address'] ?? '');
        $ruleType = sanitize_key($_POST['rule_type'] ?? 'blacklist');
        $duration = sanitize_key($_POST['block_duration'] ?? 'temporary');
        $reason = sanitize_text_field($_POST['reason'] ?? 'Manual rule');
        $notes = sanitize_textarea_field($_POST['notes'] ?? '');

        if (!IPUtils::isValidIP($ipAddress)) {
            // Handle invalid IP address error
            return;
        }

        $data = [
            'rule_type' => $ruleType,
            'duration' => $duration,
            'reason' => $reason,
            'notes' => $notes,
            'source' => 'manual'
        ];

        if ($ruleType === 'blacklist') {
            $this->ipBlocker->addBlock($ipAddress, $data);
        } elseif ($ruleType === 'whitelist') {
            $this->ipBlocker->addWhitelist($ipAddress, $data);
        }
    }

    private function renderBlockedIPsTab(array $blockedIPs): void
    {
        ?>
        <div class="ms-blocked-ips">
            <h3><?php _e('Blocked IPs', 'morden-security'); ?></h3>
            <div class="tablenav top">
                <div class="alignleft actions">
                    <button class="button action" id="bulk-unblock">
                        <?php _e('Unblock Selected', 'morden-security'); ?>
                    </button>
                </div>
                <div class="alignright">
                    <span class="displaying-num">
                        <?php printf(_n('%s item', '%s items', count($blockedIPs), 'morden-security'), number_format(count($blockedIPs))); ?>
                    </span>
                </div>
            </div>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <td class="manage-column column-cb check-column">
                            <input type="checkbox" id="cb-select-all">
                        </td>
                        <th><?php _e('IP Address', 'morden-security'); ?></th>
                        <th><?php _e('Country', 'morden-security'); ?></th>
                        <th><?php _e('Block Type', 'morden-security'); ?></th>
                        <th><?php _e('Reason', 'morden-security'); ?></th>
                        <th><?php _e('Blocked Until', 'morden-security'); ?></th>
                        <th><?php _e('Threat Score', 'morden-security'); ?></th>
                        <th><?php _e('Actions', 'morden-security'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($blockedIPs as $rule): ?>
                    <tr>
                        <th class="check-column">
                            <input type="checkbox" name="blocked_ips[]" value="<?php echo esc_attr($rule['ip_address']); ?>">
                        </th>
                        <td>
                            <code><?php echo esc_html($rule['ip_address']); ?></code>
                        </td>
                        <td>
                            <?php
                            $geoData = IPUtils::getIPGeolocation($rule['ip_address']);
                            echo esc_html($geoData['country_code']);
                            ?>
                        </td>
                        <td>
                            <span class="ms-block-type ms-block-<?php echo esc_attr($rule['rule_type']); ?>">
                                <?php echo esc_html(ucfirst(str_replace('_',' ', $rule['rule_type']))); ?>
                            </span>
                        </td>
                        <td><?php echo esc_html($rule['reason'] ?? 'Not specified'); ?></td>
                        <td>
                            <?php
                            if ($rule['block_duration'] === 'permanent') {
                                echo '<span class="ms-permanent">' . __('Permanent', 'morden-security') . '</span>';
                            } elseif ($rule['blocked_until']) {
                                echo esc_html(date('Y-m-d H:i:s', $rule['blocked_until']));
                            } else {
                                echo __('Unknown', 'morden-security');
                            }
                            ?>
                        </td>
                        <td>
                            <span class="ms-threat-score ms-score-<?php echo $this->getThreatScoreClass($rule['threat_score']); ?>">
                                <?php echo number_format($rule['threat_score']); ?>
                            </span>
                        </td>
                        <td>
                            <button class="button button-small ms-unblock-ip"
                                    data-ip="<?php echo esc_attr($rule['ip_address']); ?>">
                                <?php _e('Unblock', 'morden-security'); ?>
                            </button>
                            <button class="button button-small ms-view-logs"
                                    data-ip="<?php echo esc_attr($rule['ip_address']); ?>">
                                <?php _e('View Logs', 'morden-security'); ?>
                            </button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    private function renderWhitelistTab(array $whitelistedIPs): void
    {
        ?>
        <div class="ms-whitelist-ips">
            <h3><?php _e('Whitelisted IPs', 'morden-security'); ?></h3>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('IP Address', 'morden-security'); ?></th>
                        <th><?php _e('Added By', 'morden-security'); ?></th>
                        <th><?php _e('Added Date', 'morden-security'); ?></th>
                        <th><?php _e('Notes', 'morden-security'); ?></th>
                        <th><?php _e('Actions', 'morden-security'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($whitelistedIPs as $rule): ?>
                    <tr>
                        <td><code><?php echo esc_html($rule['ip_address']); ?></code></td>
                        <td>
                            <?php
                            $user = get_user_by('ID', $rule['created_by']);
                            echo $user ? esc_html($user->user_login) : __('System', 'morden-security');
                            ?>
                        </td>
                        <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($rule['created_at']))); ?></td>
                        <td><?php echo esc_html($rule['notes'] ?? 'None'); ?></td>
                        <td>
                            <button class="button button-small ms-remove-whitelist"
                                    data-ip="<?php echo esc_attr($rule['ip_address']); ?>">
                                <?php _e('Remove', 'morden-security'); ?>
                            </button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    private function renderAddRuleTab(): void
    {
        ?>
        <div class="ms-add-rule">
            <h3><?php _e('Add New IP Rule', 'morden-security'); ?></h3>
            <form method="post" action="" class="ms-ip-rule-form">
                <?php wp_nonce_field('ms_add_ip_rule', 'ms_ip_rule_nonce'); ?>

                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="ip_address"><?php _e('IP Address', 'morden-security'); ?></label>
                        </th>
                        <td>
                            <input type="text" id="ip_address" name="ip_address" class="regular-text"
                                   placeholder="192.168.1.1" required>
                            <p class="description">
                                <?php _e('Enter a single IP address or CIDR range (e.g., 192.168.1.0/24)', 'morden-security'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="rule_type"><?php _e('Rule Type', 'morden-security'); ?></label>
                        </th>
                        <td>
                            <select id="rule_type" name="rule_type" required>
                                <option value="blacklist"><?php _e('Block (Blacklist)', 'morden-security'); ?></option>
                                <option value="whitelist"><?php _e('Allow (Whitelist)', 'morden-security'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="block_duration"><?php _e('Duration', 'morden-security'); ?></label>
                        </th>
                        <td>
                            <select id="block_duration" name="block_duration">
                                <option value="temporary"><?php _e('Temporary', 'morden-security'); ?></option>
                                <option value="permanent"><?php _e('Permanent', 'morden-security'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="reason"><?php _e('Reason', 'morden-security'); ?></label>
                        </th>
                        <td>
                            <input type="text" id="reason" name="reason" class="regular-text"
                                   placeholder="<?php _e('Reason for this rule', 'morden-security'); ?>">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="notes"><?php _e('Notes', 'morden-security'); ?></label>
                        </th>
                        <td>
                            <textarea id="notes" name="notes" rows="3" class="large-text"
                                      placeholder="<?php _e('Optional additional notes', 'morden-security'); ?>"></textarea>
                        </td>
                    </tr>
                </table>

                <?php submit_button(__('Add IP Rule', 'morden-security')); ?>
            </form>
        </div>
        <?php
    }

    private function getBlockedIPs(): array
    {
        if (!$this->logger) {
            return [];
        }

        try {
            $stmt = $this->logger->database->prepare('
                SELECT * FROM ms_ip_rules
                WHERE rule_type IN ("blacklist", "auto_blocked")
                  AND is_active = 1
                ORDER BY created_at DESC
            ');

            if (!$stmt) {
                return [];
            }

            $result = $stmt->execute();
            $rules = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $rules[] = $row;
            }

            return $rules;
        } catch (Exception $e) {
            return [];
        }
    }

    private function getWhitelistedIPs(): array
    {
        if (!$this->logger) {
            return [];
        }

        try {
            $stmt = $this->logger->database->prepare('
                SELECT * FROM ms_ip_rules
                WHERE rule_type IN ("whitelist", "temp_whitelist")
                  AND is_active = 1
                ORDER BY created_at DESC
            ');

            if (!$stmt) {
                return [];
            }

            $result = $stmt->execute();
            $rules = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $rules[] = $row;
            }

            return $rules;
        } catch (Exception $e) {
            return [];
        }
    }

    private function getThreatScoreClass(int $score): string
    {
        if ($score >= 200) return 'critical';
        if ($score >= 100) return 'high';
        if ($score >= 50) return 'medium';
        return 'low';
    }

    private function getStatistics(): array
    {
        $securityStats = $this->logger->getSecurityStats();

        $recentEvents = $this->logger->getRecentEvents(1000, ['since' => time() - 86400]);

        $stats = [
            'blocked_requests' => $securityStats['blocked_requests'] ?? 0,
            'bot_detections' => $securityStats['bot_detections'] ?? 0,
            'firewall_blocks' => $securityStats['firewall_blocks'] ?? 0,
            'total_events' => $securityStats['total_events'] ?? 0
        ];

        if ($stats['total_events'] === 0) {
            $stats['total_events'] = count($recentEvents);
            $stats['blocked_requests'] = count(array_filter($recentEvents, fn($e) => strpos($e['action_taken'] ?? '', 'block') !== false));
            $stats['bot_detections'] = count(array_filter($recentEvents, fn($e) => strpos($e['event_type'] ?? '', 'bot') !== false));
            $stats['firewall_blocks'] = count(array_filter($recentEvents, fn($e) => $e['event_type'] === 'firewall_block'));
        }

        return $stats;
    }

    private function renderActivitiesTab(array $recentEvents): void
    {
        ?>
        <div class="ms-recent-events">
            <h3><?php _e('Recent Security Events', 'morden-security'); ?></h3>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('Date', 'morden-security'); ?></th>
                        <th><?php _e('Category', 'morden-security'); ?></th>
                        <th><?php _e('Username', 'morden-security'); ?></th>
                        <th><?php _e('IP Address', 'morden-security'); ?></th>
                        <th><?php _e('Country', 'morden-security'); ?></th>
                        <th><?php _e('Description', 'morden-security'); ?></th>
                        <th><?php _e('Action Taken', 'morden-security'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($recentEvents)) : ?>
                        <tr>
                            <td colspan="7"><?php _e('No recent events to display.', 'morden-security'); ?></td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ($recentEvents as $event) : ?>
                            <?php
                            $context = json_decode($event['context'] ?? '', true);
                            $username = $context['username'] ?? 'N/A';
                            $category = SecurityEventTypes::getCategoryForEvent($event['event_type']);
                            ?>
                            <tr>
                                <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($event['created_at']))); ?></td>
                                <td><?php echo esc_html(ucfirst($category)); ?></td>
                                <td><?php echo esc_html($username); ?></td>
                                <td><code><?php echo esc_html($event['ip_address']); ?></code></td>
                                <td><?php echo esc_html($event['country_code'] ?? 'N/A'); ?></td>
                                <td><?php echo esc_html($event['description']); ?></td>
                                <td><?php echo esc_html($event['action_taken']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    private function renderActiveSessionsTab(): void
    {
        $admins = get_users(['role' => 'administrator']);
        ?>
        <div class="ms-active-sessions">
            <h3><?php _e('Active Admin Sessions', 'morden-security'); ?></h3>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('Admin User', 'morden-security'); ?></th>
                        <th><?php _e('Role', 'morden-security'); ?></th>
                        <th><?php _e('Last Login', 'morden-security'); ?></th>
                        <th><?php _e('IP Address', 'morden-security'); ?></th>
                        <th><?php _e('Hostname', 'morden-security'); ?></th>
                        <th><?php _e('Actions', 'morden-security'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($admins)) : ?>
                        <tr>
                            <td colspan="6"><?php _e('No active admin sessions to display.', 'morden-security'); ?></td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ($admins as $admin) : ?>
                            <?php
                            $session_tokens = get_user_meta($admin->ID, 'session_tokens', true);
                            if (is_array($session_tokens) && !empty($session_tokens)) {
                                uasort($session_tokens, function($a, $b) {
                                    return $b['login'] <=> $a['login'];
                                });
                                $latest_session = reset($session_tokens);
                                $last_login_time = $latest_session['login'] ?? 0;
                                $ip_address = $latest_session['ip'] ?? 'N/A';
                                $hostname = ($ip_address !== 'N/A') ? gethostbyaddr($ip_address) : 'N/A';
                            ?>
                            <tr>
                                <td>
                                    <strong><?php echo esc_html($admin->user_login); ?></strong>
                                    <br>
                                    <?php echo esc_html($admin->display_name); ?>
                                </td>
                                <td><?php echo esc_html(implode(', ', $admin->roles)); ?></td>
                                <td><?php echo esc_html(date('Y-m-d H:i:s', $last_login_time)); ?></td>
                                <td><code><?php echo esc_html($ip_address); ?></code></td>
                                <td><?php echo esc_html($hostname); ?></td>
                                <td>
                                    <button class="button button-small ms-view-session"
                                            data-user-id="<?php echo esc_attr($admin->ID); ?>">
                                        <?php _e('Details', 'morden-security'); ?>
                                    </button>
                                    <button class="button button-small ms-block-session"
                                            data-user-id="<?php echo esc_attr($admin->ID); ?>">
                                        <?php _e('Block', 'morden-security'); ?>
                                    </button>
                                </td>
                            </tr>
                            <?php
                                }

                            ?>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
}
