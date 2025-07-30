<?php

namespace MordenSecurity\Modules\WAF;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\Validation;

if (!defined('ABSPATH')) {
    exit;
}

class RulesetManager
{
    private LoggerSQLite $logger;
    private array $loadedRulesets;
    private string $rulesetsPath;
    private array $config;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->rulesetsPath = MS_PLUGIN_PATH . 'data/rulesets/';
        $this->loadedRulesets = [];
        $this->config = [
            'auto_update' => get_option('ms_ruleset_auto_update', true),
            'update_interval' => get_option('ms_ruleset_update_interval', 86400),
            'enabled_rulesets' => get_option('ms_enabled_rulesets', ['owasp-core', 'wordpress-specific'])
        ];
    }

    public function loadAllRulesets(): array
    {
        $rulesets = [];

        foreach ($this->config['enabled_rulesets'] as $rulesetName) {
            $ruleset = $this->loadRuleset($rulesetName);
            if ($ruleset) {
                $rulesets[$rulesetName] = $ruleset;
                $this->loadedRulesets[$rulesetName] = $ruleset;
            }
        }

        return $rulesets;
    }

    public function loadRuleset(string $rulesetName): ?array
    {
        if (isset($this->loadedRulesets[$rulesetName])) {
            return $this->loadedRulesets[$rulesetName];
        }

        $rulesetFile = $this->rulesetsPath . $rulesetName . '.json';

        if (!file_exists($rulesetFile)) {
            return $this->getDefaultRuleset($rulesetName);
        }

        $content = file_get_contents($rulesetFile);
        $ruleset = json_decode($content, true);

        if (!is_array($ruleset) || !$this->validateRuleset($ruleset)) {
            error_log("MS: Invalid ruleset format for {$rulesetName}");
            return null;
        }

        $this->loadedRulesets[$rulesetName] = $ruleset;
        return $ruleset;
    }

    public function updateRuleset(string $rulesetName, array $rulesetData): bool
    {
        if (!$this->validateRuleset($rulesetData)) {
            return false;
        }

        $rulesetFile = $this->rulesetsPath . $rulesetName . '.json';

        if (!is_dir($this->rulesetsPath)) {
            wp_mkdir_p($this->rulesetsPath);
        }

        $jsonData = json_encode($rulesetData, JSON_PRETTY_PRINT);
        $success = file_put_contents($rulesetFile, $jsonData, LOCK_EX) !== false;

        if ($success) {
            $this->loadedRulesets[$rulesetName] = $rulesetData;
            $this->logRulesetAction($rulesetName, 'updated');
        }

        return $success;
    }

    public function enableRuleset(string $rulesetName): bool
    {
        if (!in_array($rulesetName, $this->config['enabled_rulesets'])) {
            $this->config['enabled_rulesets'][] = $rulesetName;
            $success = update_option('ms_enabled_rulesets', $this->config['enabled_rulesets']);

            if ($success) {
                $this->logRulesetAction($rulesetName, 'enabled');
            }

            return $success;
        }

        return true;
    }

    public function disableRuleset(string $rulesetName): bool
    {
        $key = array_search($rulesetName, $this->config['enabled_rulesets']);

        if ($key !== false) {
            unset($this->config['enabled_rulesets'][$key]);
            $this->config['enabled_rulesets'] = array_values($this->config['enabled_rulesets']);
            $success = update_option('ms_enabled_rulesets', $this->config['enabled_rulesets']);

            if ($success) {
                unset($this->loadedRulesets[$rulesetName]);
                $this->logRulesetAction($rulesetName, 'disabled');
            }

            return $success;
        }

        return true;
    }

    public function getRulesetStatistics(): array
    {
        $stats = [
            'total_rulesets' => count($this->getAvailableRulesets()),
            'enabled_rulesets' => count($this->config['enabled_rulesets']),
            'total_rules' => 0,
            'rules_by_category' => [],
            'rules_by_severity' => []
        ];

        foreach ($this->loadedRulesets as $rulesetName => $ruleset) {
            $rules = $ruleset['rules'] ?? [];
            $stats['total_rules'] += count($rules);

            foreach ($rules as $rule) {
                $category = $rule['category'] ?? 'unknown';
                $severity = $rule['severity'] ?? 1;

                $stats['rules_by_category'][$category] =
                    ($stats['rules_by_category'][$category] ?? 0) + 1;

                $stats['rules_by_severity'][$severity] =
                    ($stats['rules_by_severity'][$severity] ?? 0) + 1;
            }
        }

        return $stats;
    }

    public function getAvailableRulesets(): array
    {
        $rulesets = [];

        if (is_dir($this->rulesetsPath)) {
            $files = glob($this->rulesetsPath . '*.json');

            foreach ($files as $file) {
                $rulesetName = basename($file, '.json');
                $rulesets[] = $rulesetName;
            }
        }

        $defaultRulesets = ['owasp-core', 'wordpress-specific', 'ecommerce-protection'];
        foreach ($defaultRulesets as $defaultRuleset) {
            if (!in_array($defaultRuleset, $rulesets)) {
                $rulesets[] = $defaultRuleset;
            }
        }

        return array_unique($rulesets);
    }

    public function checkForUpdates(): array
    {
        $updates = [];

        foreach ($this->config['enabled_rulesets'] as $rulesetName) {
            $currentVersion = $this->getRulesetVersion($rulesetName);
            $latestVersion = $this->getLatestRulesetVersion($rulesetName);

            if (version_compare($currentVersion, $latestVersion, '<')) {
                $updates[] = [
                    'ruleset' => $rulesetName,
                    'current_version' => $currentVersion,
                    'latest_version' => $latestVersion
                ];
            }
        }

        return $updates;
    }

    public function importRuleset(string $rulesetName, array $rulesetData): bool
    {
        if (!$this->validateRuleset($rulesetData)) {
            return false;
        }

        $success = $this->updateRuleset($rulesetName, $rulesetData);

        if ($success) {
            $this->enableRuleset($rulesetName);
            $this->logRulesetAction($rulesetName, 'imported');
        }

        return $success;
    }

    public function exportRuleset(string $rulesetName): ?array
    {
        $ruleset = $this->loadRuleset($rulesetName);

        if ($ruleset) {
            return [
                'metadata' => $ruleset['metadata'] ?? [],
                'rules' => $ruleset['rules'] ?? []
            ];
        }

        return null;
    }

private function validateRuleset(array $ruleset): bool
{
    // Check for required top-level keys
    if (!isset($ruleset['metadata']) || !isset($ruleset['rules'])) {
        error_log("MS: Ruleset validation failed - missing metadata or rules key");
        return false;
    }

    // Check metadata is array
    if (!is_array($ruleset['metadata'])) {
        error_log("MS: Ruleset validation failed - metadata is not an array");
        return false;
    }

    // Check rules is array
    if (!is_array($ruleset['rules'])) {
        error_log("MS: Ruleset validation failed - rules is not an array");
        return false;
    }

    // Validate each rule
    foreach ($ruleset['rules'] as $index => $rule) {
        if (!$this->validateRule($rule)) {
            error_log("MS: Ruleset validation failed - invalid rule at index {$index}");
            error_log("MS: Rule data: " . json_encode($rule));
            return false;
        }
    }

    return true;
}

private function validateRule(array $rule): bool
{
    $requiredFields = ['id', 'name', 'pattern', 'severity', 'action', 'message'];

    foreach ($requiredFields as $field) {
        if (!isset($rule[$field])) {
            error_log("MS: Rule validation failed - missing required field: {$field}");
            return false;
        }
    }

    // Validate severity
    if (!is_numeric($rule['severity']) || $rule['severity'] < 1 || $rule['severity'] > 10) {
        error_log("MS: Rule validation failed - invalid severity: " . $rule['severity']);
        return false;
    }

    // Validate action
    $validActions = ['allow', 'block', 'monitor', 'challenge'];
    if (!in_array($rule['action'], $validActions, true)) {
        error_log("MS: Rule validation failed - invalid action: " . $rule['action']);
        return false;
    }

    // Validate pattern (basic regex check)
    if (empty($rule['pattern'])) {
        error_log("MS: Rule validation failed - empty pattern");
        return false;
    }

    return true;
    }

    private function getRulesetVersion(string $rulesetName): string
    {
        $ruleset = $this->loadRuleset($rulesetName);
        return $ruleset['metadata']['version'] ?? '1.0.0';
    }

    private function getLatestRulesetVersion(string $rulesetName): string
    {
        return '1.0.0';
    }

private function getDefaultRuleset(string $rulesetName): ?array
{
    $defaults = [
        'owasp-core' => [
            'metadata' => [
                'name' => 'OWASP Core Rule Set',
                'version' => '3.3.4',
                'description' => 'Core OWASP security rules for web application protection',
                'author' => 'OWASP CRS Project',
                'created_at' => date('Y-m-d'),
                'updated_at' => date('Y-m-d')
            ],
            'rules' => [
                [
                    'id' => 'OWASP_942100',
                    'name' => 'SQL Injection Detection',
                    'pattern' => '(?i)(?:union\\s+(?:all\\s+)?select|select\\s+.*\\s+from|insert\\s+into)',
                    'severity' => 5,
                    'action' => 'block',
                    'message' => 'SQL injection attempt detected',
                    'category' => 'sql_injection',
                    'enabled' => true,
                    'targets' => ['all']
                ],
                [
                    'id' => 'OWASP_941100',
                    'name' => 'XSS Detection',
                    'pattern' => '(?i)(?:<script|javascript:|on(?:load|error|click)\\s*=)',
                    'severity' => 4,
                    'action' => 'block',
                    'message' => 'Cross-site scripting (XSS) attempt detected',
                    'category' => 'xss',
                    'enabled' => true,
                    'targets' => ['all']
                ],
                [
                    'id' => 'OWASP_930100',
                    'name' => 'Path Traversal Detection',
                    'pattern' => '\\.\\.',
                    'severity' => 5,
                    'action' => 'block',
                    'message' => 'Path traversal attack detected',
                    'category' => 'lfi',
                    'enabled' => true,
                    'targets' => ['uri', 'query_string']
                ]
            ]
        ],
        'wordpress-specific' => [
            'metadata' => [
                'name' => 'WordPress Specific Rules',
                'version' => '1.2.0',
                'description' => 'WordPress-specific security rules',
                'author' => 'Morden Security',
                'created_at' => date('Y-m-d'),
                'updated_at' => date('Y-m-d')
            ],
            'rules' => [
                [
                    'id' => 'WP_001',
                    'name' => 'WordPress Config Access',
                    'pattern' => 'wp-config\\.php',
                    'severity' => 5,
                    'action' => 'block',
                    'message' => 'Attempt to access wp-config.php',
                    'category' => 'file_access',
                    'enabled' => true,
                    'targets' => ['uri']
                ],
                [
                    'id' => 'WP_002',
                    'name' => 'WordPress Admin Brute Force',
                    'pattern' => 'wp-admin.*wp-login\\.php.*pwd',
                    'severity' => 4,
                    'action' => 'monitor',
                    'message' => 'Potential WordPress admin brute force attempt',
                    'category' => 'brute_force',
                    'enabled' => true,
                    'targets' => ['uri', 'post_data']
                ]
            ]
        ]
    ];

    return $defaults[$rulesetName] ?? null;
}

    private function logRulesetAction(string $rulesetName, string $action): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'ruleset_' . $action,
            'severity' => 2,
            'ip_address' => '127.0.0.1',
            'message' => "WAF ruleset {$action}: {$rulesetName}",
            'context' => [
                'ruleset_name' => $rulesetName,
                'action' => $action,
                'user_id' => get_current_user_id()
            ],
            'action_taken' => 'ruleset_' . $action
        ]);
    }
}
