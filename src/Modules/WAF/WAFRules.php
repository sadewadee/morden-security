<?php

namespace MordenSecurity\Modules\WAF;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Modules\WAF\RulesetManager;
use MordenSecurity\Modules\WAF\CustomRules;

class WAFRules {
    private $logger;
    private $rulesetManager;
    private $customRules;
    private $loadedRules;

    public function __construct($logger, $rulesetManager, $customRules) {
        $this->logger = $logger;
        $this->rulesetManager = $rulesetManager;
        $this->customRules = $customRules;
        $this->loadAllRules();
    }

    public function evaluateRequest(array $requestData): array {
        $violations = [];

        // Evaluasi ruleset standar
        foreach ($this->loadedRules['standard'] as $ruleGroup => $rules) {
            $violations = array_merge($violations, $this->evaluateRuleGroup($rules, $requestData, $ruleGroup));
        }

        // Evaluasi custom rules
        $customViolations = $this->customRules->evaluateRules($requestData);
        $violations = array_merge($violations, $customViolations);

        // Urutkan berdasarkan severity
        usort($violations, fn($a, $b) => $b['severity'] <=> $a['severity']);

        return $violations;
    }

    public function addRuleGroup(string $groupName, array $rules): bool {
        if ($this->validateRuleGroup($rules)) {
            $this->loadedRules['standard'][$groupName] = $rules;
            return true;
        }
        return false;
    }

    public function removeRuleGroup(string $groupName): bool {
        if (isset($this->loadedRules['standard'][$groupName])) {
            unset($this->loadedRules['standard'][$groupName]);
            return true;
        }
        return false;
    }

    public function getActiveRulesCount(): array {
        $count = [
            'standard' => 0,
            'custom' => count($this->customRules->getRules()),
            'total' => 0
        ];

        foreach ($this->loadedRules['standard'] as $rules) {
            $count['standard'] += count(array_filter($rules, fn($r) => $r['enabled'] ?? true));
        }

        $count['total'] = $count['standard'] + $count['custom'];
        return $count;
    }

    private function loadAllRules(): void {
        $this->loadedRules = [
            'standard' => [],
            'builtin' => $this->getBuiltinRules()
        ];

        // Load rulesets dari RulesetManager
        $rulesets = $this->rulesetManager->loadAllRulesets();
        foreach ($rulesets as $rulesetName => $ruleset) {
            if (isset($ruleset['rules']) && is_array($ruleset['rules'])) {
                $this->loadedRules['standard'][$rulesetName] = $ruleset['rules'];
            }
        }
    }

    private function evaluateRuleGroup(array $rules, array $requestData, string $groupName): array {
        $violations = [];

        foreach ($rules as $rule) {
            if (!($rule['enabled'] ?? true)) {
                continue;
            }

            $result = $this->evaluateRule($rule, $requestData);
            if ($result['triggered']) {
                $violations[] = [
                    'rule_id' => $rule['id'],
                    'rule_name' => $rule['name'] ?? 'Unknown Rule',
                    'rule_group' => $groupName,
                    'severity' => $rule['severity'] ?? 5,
                    'message' => $rule['message'] ?? 'Rule triggered',
                    'category' => $rule['category'] ?? 'security',
                    'matched_data' => $result['matched_data'],
                    'source_field' => $result['source'],
                    'action' => $rule['action'] ?? 'monitor'
                ];

                // Update hit statistics
                $this->updateRuleStatistics($rule['id'], $groupName);
            }
        }

        return $violations;
    }

    private function evaluateRule(array $rule, array $requestData): array {
        if (!$this->isValidRule($rule)) {
            return ['triggered' => false];
        }

        $pattern = $rule['pattern'];
        $flags = $rule['flags'] ?? 'i';
        $targets = $rule['targets'] ?? ['all'];

        foreach ($requestData as $source => $data) {
            if (!$this->shouldCheckTarget($targets, $source)) {
                continue;
            }

            if (is_string($data) && $this->matchesPattern($pattern, $data, $flags)) {
                return [
                    'triggered' => true,
                    'matched_data' => $this->extractMatchedData($pattern, $data, $flags),
                    'source' => $source
                ];
            }
        }

        return ['triggered' => false];
    }

    private function matchesPattern(string $pattern, string $data, string $flags): bool {
        $compiledPattern = "/{$pattern}/{$flags}";

        // Suppress errors untuk pattern yang tidak valid
        set_error_handler(function() { return true; });
        $result = @preg_match($compiledPattern, $data);
        restore_error_handler();

        return $result === 1;
    }

    private function extractMatchedData(string $pattern, string $data, string $flags): string {
        $compiledPattern = "/{$pattern}/{$flags}";

        set_error_handler(function() { return true; });
        $matches = [];
        @preg_match($compiledPattern, $data, $matches);
        restore_error_handler();

        return $matches[0] ?? substr($data, 0, 100);
    }

    private function shouldCheckTarget(array $targets, string $source): bool {
        return in_array('all', $targets) || in_array($source, $targets);
    }

    private function isValidRule(array $rule): bool {
        return isset($rule['id'], $rule['pattern']) && !empty($rule['pattern']);
    }

    private function validateRuleGroup(array $rules): bool {
        foreach ($rules as $rule) {
            if (!$this->isValidRule($rule)) {
                return false;
            }
        }
        return true;
    }

    private function updateRuleStatistics(string $ruleId, string $groupName): void {
        // Update statistics untuk monitoring
        $stats = get_option('ms_waf_rule_stats', []);
        $key = "{$groupName}:{$ruleId}";

        if (!isset($stats[$key])) {
            $stats[$key] = ['hits' => 0, 'last_hit' => 0];
        }

        $stats[$key]['hits']++;
        $stats[$key]['last_hit'] = time();

        update_option('ms_waf_rule_stats', $stats);
    }

    private function getBuiltinRules(): array {
        return [
            'emergency' => [
                [
                    'id' => 'EMERGENCY_001',
                    'name' => 'Critical SQL Injection',
                    'pattern' => '(union\s+select|drop\s+table|truncate\s+table)',
                    'severity' => 10,
                    'action' => 'block',
                    'message' => 'Critical SQL injection attempt detected',
                    'category' => 'sql_injection',
                    'enabled' => true,
                    'targets' => ['all']
                ],
                [
                    'id' => 'EMERGENCY_002',
                    'name' => 'Remote Code Execution',
                    'pattern' => '(eval\s*\(|exec\s*\(|system\s*\(|shell_exec)',
                    'severity' => 10,
                    'action' => 'block',
                    'message' => 'Remote code execution attempt detected',
                    'category' => 'code_injection',
                    'enabled' => true,
                    'targets' => ['all']
                ]
            ]
        ];
    }
}
