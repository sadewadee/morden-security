<?php

namespace MordenSecurity\Modules\WAF;

if (!defined('ABSPATH')) {
    exit;
}

class WAFRules
{
    private array $rules;
    private array $customRules;
    private string $rulesPath;

    public function __construct()
    {
        $this->rulesPath = MS_PLUGIN_PATH . 'data/rulesets/';
        $this->loadRules();
        $this->loadCustomRules();
    }

    public function evaluateRequest(array $requestData): array
    {
        $violations = [];

        foreach ($this->rules as $ruleGroup => $rules) {
            foreach ($rules as $rule) {
                $result = $this->evaluateRule($rule, $requestData);
                if ($result['triggered']) {
                    $violations[] = [
                        'rule_id' => $rule['id'],
                        'rule_group' => $ruleGroup,
                        'severity' => $rule['severity'],
                        'message' => $rule['message'],
                        'matched_data' => $result['matched_data'],
                        'action' => $rule['action']
                    ];
                }
            }
        }

        foreach ($this->customRules as $rule) {
            $result = $this->evaluateRule($rule, $requestData);
            if ($result['triggered']) {
                $violations[] = [
                    'rule_id' => $rule['id'],
                    'rule_group' => 'custom',
                    'severity' => $rule['severity'],
                    'message' => $rule['message'],
                    'matched_data' => $result['matched_data'],
                    'action' => $rule['action']
                ];
            }
        }

        return $violations;
    }

    public function addCustomRule(array $ruleData): bool
    {
        $rule = [
            'id' => 'custom_' . time() . '_' . wp_rand(1000, 9999),
            'name' => $ruleData['name'],
            'pattern' => $ruleData['pattern'],
            'severity' => $ruleData['severity'] ?? 5,
            'action' => $ruleData['action'] ?? 'block',
            'message' => $ruleData['message'] ?? 'Custom rule triggered',
            'enabled' => true,
            'created_at' => time()
        ];

        $this->customRules[] = $rule;
        return $this->saveCustomRules();
    }

    public function removeCustomRule(string $ruleId): bool
    {
        $this->customRules = array_filter(
            $this->customRules,
            fn($rule) => $rule['id'] !== $ruleId
        );

        return $this->saveCustomRules();
    }

    public function getActiveRules(): array
    {
        $activeRules = [];

        foreach ($this->rules as $group => $rules) {
            $activeRules[$group] = array_filter($rules, fn($rule) => $rule['enabled'] ?? true);
        }

        $activeRules['custom'] = array_filter($this->customRules, fn($rule) => $rule['enabled'] ?? true);

        return $activeRules;
    }

    private function loadRules(): void
    {
        $this->rules = [
            'owasp_core' => $this->loadRulesetFile('owasp-core.json'),
            'wordpress_specific' => $this->loadRulesetFile('wordpress-specific.json'),
            'ecommerce_protection' => $this->loadRulesetFile('ecommerce-protection.json')
        ];
    }

    private function loadRulesetFile(string $filename): array
    {
        $filePath = $this->rulesPath . $filename;

        if (!file_exists($filePath)) {
            return $this->getDefaultRuleset($filename);
        }

        $content = file_get_contents($filePath);
        $rules = json_decode($content, true);

        return is_array($rules) ? $rules : [];
    }

    private function loadCustomRules(): void
    {
        $customRules = get_option('ms_custom_waf_rules', []);
        $this->customRules = is_array($customRules) ? $customRules : [];
    }

    private function saveCustomRules(): bool
    {
        return update_option('ms_custom_waf_rules', $this->customRules);
    }

    private function evaluateRule(array $rule, array $requestData): array
    {
        if (!($rule['enabled'] ?? true)) {
            return ['triggered' => false];
        }

        $pattern = $rule['pattern'];
        $flags = $rule['flags'] ?? 'i';

        foreach ($requestData as $source => $data) {
            if (preg_match("/{$pattern}/{$flags}", $data, $matches)) {
                return [
                    'triggered' => true,
                    'matched_data' => $matches[0] ?? '',
                    'source' => $source
                ];
            }
        }

        return ['triggered' => false];
    }

    private function getDefaultRuleset(string $filename): array
    {
        switch ($filename) {
            case 'owasp-core.json':
                return [
                    [
                        'id' => 'OWASP_001',
                        'name' => 'SQL Injection Detection',
                        'pattern' => '(union.*select|select.*from|insert.*into)',
                        'severity' => 8,
                        'action' => 'block',
                        'message' => 'SQL injection attempt detected',
                        'enabled' => true
                    ],
                    [
                        'id' => 'OWASP_002',
                        'name' => 'XSS Detection',
                        'pattern' => '(<script|javascript:|on\w+\s*=)',
                        'severity' => 7,
                        'action' => 'block',
                        'message' => 'Cross-site scripting attempt detected',
                        'enabled' => true
                    ]
                ];

            case 'wordpress-specific.json':
                return [
                    [
                        'id' => 'WP_001',
                        'name' => 'WordPress Config Access',
                        'pattern' => '(wp-config\.php|\.htaccess)',
                        'severity' => 9,
                        'action' => 'block',
                        'message' => 'Attempt to access WordPress configuration files',
                        'enabled' => true
                    ],
                    [
                        'id' => 'WP_002',
                        'name' => 'Plugin Directory Traversal',
                        'pattern' => '(\/wp-content\/plugins\/.*\.\.\/)',
                        'severity' => 8,
                        'action' => 'block',
                        'message' => 'Directory traversal in plugins directory',
                        'enabled' => true
                    ]
                ];

            case 'ecommerce-protection.json':
                return [
                    [
                        'id' => 'EC_001',
                        'name' => 'Credit Card Pattern',
                        'pattern' => '\b(?:\d{4}[-\s]?){3}\d{4}\b',
                        'severity' => 6,
                        'action' => 'monitor',
                        'message' => 'Credit card pattern detected in request',
                        'enabled' => true
                    ]
                ];

            default:
                return [];
        }
    }
}
