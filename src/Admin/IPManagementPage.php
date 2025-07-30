<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class IPManagementPage
{
    private LoggerSQLite $logger;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
    }

    public function render(): void
    {
        $activeTab = sanitize_key($_GET['tab'] ?? 'blocked');
        $blockedIPs = $this->getBlockedIPs();
        $whitelistedIPs = $this->getWhitelistedIPs();

        ?>
        <div class="wrap">
            <h1><?php _e('IP Management', 'morden-security'); ?></h1>

            <nav class="nav-tab-wrapper">
                <a href="?page=morden-security-ips&tab=blocked"
                   class="nav-tab <?php echo $activeTab === 'blocked' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Blocked IPs', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-ips&tab=whitelist"
                   class="nav-tab <?php echo $activeTab === 'whitelist' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Whitelist', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-ips&tab=add"
                   class="nav-tab <?php echo $activeTab === 'add' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Add Rule', 'morden-security'); ?>
                </a>
            </nav>

            <div class="tab-content">
                <?php
                switch ($activeTab) {
                    case 'blocked':
                        $this->renderBlockedIPsTab($blockedIPs);
                        break;
                    case 'whitelist':
                        $this->renderWhitelistTab($whitelistedIPs);
                        break;
                    case 'add':
                        $this->renderAddRuleTab();
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    private function renderBlockedIPsTab(array $blockedIPs): void
    {
        ?>
        <div class="ms-blocked-ips">
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
                                <?php echo esc_html(ucfirst(str_replace('_', ' ', $rule['rule_type']))); ?>
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
                WHERE rule_type = "whitelist"
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
}
