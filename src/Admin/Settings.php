<?php

namespace MordenSecurity\Admin;

if (!defined('ABSPATH')) {
    exit;
}

class Settings
{
    private array $settings;

    public function __construct()
    {
        $this->settings = $this->getDefaultSettings();
    }

    public function render(): void
    {
        $activeTab = sanitize_key($_GET['tab'] ?? 'general');

        ?>
        <div class="wrap">
            <h1><?php _e('Morden Security Settings', 'morden-security'); ?></h1>

            <nav class="nav-tab-wrapper">
                <a href="?page=morden-security-settings&tab=general"
                   class="nav-tab <?php echo $activeTab === 'general' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('General', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=firewall"
                   class="nav-tab <?php echo $activeTab === 'firewall' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Firewall', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=bot-detection"
                   class="nav-tab <?php echo $activeTab === 'bot-detection' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Bot Detection', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-settings&tab=updates"
                   class="nav-tab <?php echo $activeTab === 'updates' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Updates', 'morden-security'); ?>
                </a>
            </nav>

            <form method="post" action="" class="ms-settings-form">
                <?php wp_nonce_field('ms_save_settings', 'ms_settings_nonce'); ?>

                <div class="tab-content">
                    <?php
                    switch ($activeTab) {
                        case 'general':
                            $this->renderGeneralTab();
                            break;
                        case 'firewall':
                            $this->renderFirewallTab();
                            break;
                        case 'bot-detection':
                            $this->renderBotDetectionTab();
                            break;
                        case 'updates':
                            $this->renderUpdatesTab();
                            break;
                    }
                    ?>
                </div>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    private function renderGeneralTab(): void
    {
        ?>
        <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="ms_logging_enabled"><?php _e('Enable Logging', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_logging_enabled" name="ms_logging_enabled" value="1"
                           <?php checked(get_option('ms_logging_enabled', true)); ?>>
                    <p class="description">
                        <?php _e('Log all security events to database for analysis.', 'morden-security'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_auto_blocking_enabled"><?php _e('Auto IP Blocking', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_auto_blocking_enabled" name="ms_auto_blocking_enabled" value="1"
                           <?php checked(get_option('ms_auto_blocking_enabled', true)); ?>>
                    <p class="description">
                        <?php _e('Automatically block IPs based on threat score.', 'morden-security'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_temp_block_duration"><?php _e('Temporary Block Duration', 'morden-security'); ?></label>
                </th>
                <td>
                    <select id="ms_temp_block_duration" name="ms_temp_block_duration">
                        <option value="3600" <?php selected(get_option('ms_temp_block_duration', 3600), 3600); ?>>
                            <?php _e('1 Hour', 'morden-security'); ?>
                        </option>
                        <option value="7200" <?php selected(get_option('ms_temp_block_duration', 3600), 7200); ?>>
                            <?php _e('2 Hours', 'morden-security'); ?>
                        </option>
                        <option value="21600" <?php selected(get_option('ms_temp_block_duration', 3600), 21600); ?>>
                            <?php _e('6 Hours', 'morden-security'); ?>
                        </option>
                        <option value="86400" <?php selected(get_option('ms_temp_block_duration', 3600), 86400); ?>>
                            <?php _e('24 Hours', 'morden-security'); ?>
                        </option>
                    </select>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_perm_block_threshold"><?php _e('Permanent Block Threshold', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="number" id="ms_perm_block_threshold" name="ms_perm_block_threshold"
                           value="<?php echo esc_attr(get_option('ms_perm_block_threshold', 5)); ?>" min="1" max="20">
                    <p class="description">
                        <?php _e('Number of violations before permanent block.', 'morden-security'); ?>
                    </p>
                </td>
            </tr>
        </table>
        <?php
    }

    private function renderFirewallTab(): void
    {
        ?>
        <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="ms_firewall_enabled"><?php _e('Enable Firewall', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_firewall_enabled" name="ms_firewall_enabled" value="1"
                           <?php checked(get_option('ms_firewall_enabled', true)); ?>>
                    <p class="description">
                        <?php _e('Enable web application firewall protection.', 'morden-security'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_sql_injection_protection"><?php _e('SQL Injection Protection', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_sql_injection_protection" name="ms_sql_injection_protection" value="1"
                           <?php checked(get_option('ms_sql_injection_protection', true)); ?>>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_xss_protection"><?php _e('XSS Protection', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_xss_protection" name="ms_xss_protection" value="1"
                           <?php checked(get_option('ms_xss_protection', true)); ?>>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_lfi_protection"><?php _e('Local File Inclusion Protection', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_lfi_protection" name="ms_lfi_protection" value="1"
                           <?php checked(get_option('ms_lfi_protection', true)); ?>>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_rfi_protection"><?php _e('Remote File Inclusion Protection', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_rfi_protection" name="ms_rfi_protection" value="1"
                           <?php checked(get_option('ms_rfi_protection', true)); ?>>
                </td>
            </tr>
        </table>
        <?php
    }

    private function renderBotDetectionTab(): void
    {
        ?>
        <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="ms_bot_detection_enabled"><?php _e('Enable Bot Detection', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_bot_detection_enabled" name="ms_bot_detection_enabled" value="1"
                           <?php checked(get_option('ms_bot_detection_enabled', true)); ?>>
                    <p class="description">
                        <?php _e('Detect and block malicious bots.', 'morden-security'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_bot_challenge_threshold"><?php _e('Challenge Threshold', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="number" id="ms_bot_challenge_threshold" name="ms_bot_challenge_threshold"
                           value="<?php echo esc_attr(get_option('ms_bot_challenge_threshold', 70)); ?>" min="1" max="100">
                    <p class="description">
                        <?php _e('Confidence level to challenge suspicious bots (1-100).', 'morden-security'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_bot_block_threshold"><?php _e('Block Threshold', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="number" id="ms_bot_block_threshold" name="ms_bot_block_threshold"
                           value="<?php echo esc_attr(get_option('ms_bot_block_threshold', 90)); ?>" min="1" max="100">
                    <p class="description">
                        <?php _e('Confidence level to block malicious bots (1-100).', 'morden-security'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_aggressive_bot_detection"><?php _e('Aggressive Detection', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_aggressive_bot_detection" name="ms_aggressive_bot_detection" value="1"
                           <?php checked(get_option('ms_aggressive_bot_detection', false)); ?>>
                    <p class="description">
                        <?php _e('Enable more aggressive bot detection (may cause false positives).', 'morden-security'); ?>
                    </p>
                </td>
            </tr>
        </table>
        <?php
    }

    private function renderUpdatesTab(): void
    {
        ?>
        <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="ms_github_updates_enabled"><?php _e('Enable GitHub Updates', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_github_updates_enabled" name="ms_github_updates_enabled" value="1"
                           <?php checked(get_option('ms_github_updates_enabled', true)); ?>>
                    <p class="description">
                        <?php _e('Check for updates from GitHub repository.', 'morden-security'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_auto_updates_enabled"><?php _e('Auto Updates', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="checkbox" id="ms_auto_updates_enabled" name="ms_auto_updates_enabled" value="1"
                           <?php checked(get_option('ms_auto_updates_enabled', false)); ?>>
                    <p class="description">
                        <?php _e('Automatically install updates when available.', 'morden-security'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="ms_github_token"><?php _e('GitHub Token', 'morden-security'); ?></label>
                </th>
                <td>
                    <input type="password" id="ms_github_token" name="ms_github_token" class="regular-text"
                           value="<?php echo esc_attr(get_option('ms_github_token', '')); ?>">
                    <p class="description">
                        <?php _e('Optional: GitHub personal access token for private repositories.', 'morden-security'); ?>
                    </p>
                </td>
            </tr>
        </table>
        <?php
    }

    private function getDefaultSettings(): array
    {
        return [
            'ms_logging_enabled' => true,
            'ms_firewall_enabled' => true,
            'ms_auto_blocking_enabled' => true,
            'ms_bot_detection_enabled' => true,
            'ms_sql_injection_protection' => true,
            'ms_xss_protection' => true,
            'ms_lfi_protection' => true,
            'ms_rfi_protection' => true,
            'ms_temp_block_duration' => 3600,
            'ms_perm_block_threshold' => 5,
            'ms_bot_challenge_threshold' => 70,
            'ms_bot_block_threshold' => 90,
            'ms_github_updates_enabled' => true
        ];
    }
}
