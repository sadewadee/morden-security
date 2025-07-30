<?php

namespace MordenSecurity\Modules\WAF;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\Validation;

if (!defined('ABSPATH')) {
    exit;
}

class CustomRules
{
    private LoggerSQLite $logger;
    private array $customRules;
    private string $rulesOptionKey = 'ms_custom_waf_rules';

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->loadCustomRules();
    }

    public function addRule(array $ruleData): array
    {
        $rule = $this->validateAndSanitizeRule($ruleData);

        if (!$rule['valid']) {
            return ['success' => false, 'errors' => $rule['errors']];
        }

        $newRule = [
            'id' => 'custom_' . time() . '_' . wp_rand(1000, 9999),
            'name' => $rule['data']['name'],
            'pattern' => $rule['data']['pattern'],
            'flags' => $rule['data']['flags'],
            'severity' => $rule['data']['severity'],
            'action' => $rule['data']['action'],
            'message' => $rule['data']['message'],
            'category' => $rule['data']['category'],
            'enabled' => $rule['data']['enabled'],
            'targets' => $rule['data']['targets'],
            'conditions' => $rule['data']['conditions'],
            'created_at' => time(),
            'created_by' => get_current_user_id(),
            'hit_count' => 0,
            'last_triggered' => null
        ];

        $this->customRules[] = $newRule;
        $success = $this->saveCustomRules();

        if ($success) {
            $this->logRuleAction($newRule, 'created');
        }

        return [
            'success' => $success,
            'rule_id' => $newRule['id'],
            'message' => $success ? 'Rule created successfully' : 'Failed to create rule'
        ];
    }

    public function updateRule(string $ruleId, array $ruleData): array
    {
        $ruleIndex = $this->findRuleIndex($ruleId);
        if ($ruleIndex === false) {
            return ['success' => false, 'message' => 'Rule not found'];
        }

        $validatedRule = $this->validateAndSanitizeRule($ruleData);
        if (!$validatedRule['valid']) {
            return ['success' => false, 'errors' => $validatedRule['errors']];
        }

        $oldRule = $this->customRules[$ruleIndex];

        $this->customRules[$ruleIndex] = array_merge($oldRule, [
            'name' => $validatedRule['data']['name'],
            'pattern' => $validatedRule['data']['pattern'],
            'flags' => $validatedRule['data']['flags'],
            'severity' => $validatedRule['data']['severity'],
            'action' => $validatedRule['data']['action'],
            'message' => $validatedRule['data']['message'],
            'category' => $validatedRule['data']['category'],
            'enabled' => $validatedRule['data']['enabled'],
            'targets' => $validatedRule['data']['targets'],
            'conditions' => $validatedRule['data']['conditions'],
            'updated_at' => time(),
            'updated_by' => get_current_user_id()
        ]);

        $success = $this->saveCustomRules();

        if ($success) {
            $this->logRuleAction($this->customRules[$ruleIndex], 'updated');
        }

        return [
            'success' => $success,
            'message' => $success ? 'Rule updated successfully' : 'Failed to update rule'
        ];
    }

    public function deleteRule(string $ruleId): array
    {
        $ruleIndex = $this->findRuleIndex($ruleId);
        if ($ruleIndex === false) {
            return ['success' => false, 'message' => 'Rule not found'];
        }

        $deletedRule = $this->customRules[$ruleIndex];
        unset($this->customRules[$ruleIndex]);
        $this->customRules = array_values($this->customRules);

        $success = $this->saveCustomRules();

        if ($success) {
            $this->logRuleAction($deletedRule, 'deleted');
        }

        return [
            'success' => $success,
            'message' => $success ? 'Rule deleted successfully' : 'Failed to delete rule'
        ];
    }

    public function toggleRule(string $ruleId): array
    {
        $ruleIndex = $this->findRuleIndex($ruleId);
        if ($ruleIndex === false) {
            return ['success' => false, 'message' => 'Rule not found'];
        }

        $this->customRules[$ruleIndex]['enabled'] = !$this->customRules[$ruleIndex]['enabled'];
        $this->customRules[$ruleIndex]['updated_at'] = time();
        $this->customRules[$ruleIndex]['updated_by'] = get_current_user_id();

        $success = $this->saveCustomRules();

        if ($success) {
            $action = $this->customRules[$ruleIndex]['enabled'] ? 'enabled' : 'disabled';
            $this->logRuleAction($this->customRules[$ruleIndex], $action);
        }

        return [
            'success' => $success,
            'message' => $success ? 'Rule status updated successfully' : 'Failed to update rule status'
        ];
    }

    public function getRules(): array
    {
        return array_values($this->customRules);
    }

    public function getRule(string $ruleId): ?array
    {
        $ruleIndex = $this->findRuleIndex($ruleId);
        return $ruleIndex !== false ? $this->customRules[$ruleIndex] : null;
    }

    public function evaluateRules(array $requestData): array
    {
        $violations = [];

        foreach ($this->customRules as $rule) {
            if (!$rule['enabled']) {
                continue;
            }

            $result = $this->evaluateRule($rule, $requestData);
            if ($result['triggered']) {
                $this->incrementHitCount($rule['id']);

                $violations[] = [
                    'rule_id' => $rule['id'],
                    'rule_name' => $rule['name'],
                    'severity' => $rule['severity'],
                    'action' => $rule['action'],
                    'message' => $rule['message'],
                    'category' => $rule['category'],
                    'matched_data' => $result['matched_data'],
                    'source' => $result['source']
                ];
            }
        }

        return $violations;
    }

    public function importRules(array $rules): array
    {
        $imported = 0;
        $errors = [];

        foreach ($rules as $ruleData) {
            $result = $this->addRule($ruleData);
            if ($result['success']) {
                $imported++;
            } else {
                $errors[] = $result['errors'] ?? ['Unknown error'];
            }
        }

        return [
            'imported' => $imported,
            'errors' => $errors,
            'total' => count($rules)
        ];
    }

    public function exportRules(): array
    {
        return array_map(function($rule) {
            unset($rule['hit_count'], $rule['last_triggered'], $rule['created_by'], $rule['updated_by']);
            return $rule;
        }, $this->customRules);
    }

    private function validateAndSanitizeRule(array $ruleData): array
    {
        $errors = [];
        $data = [];

        $data['name'] = isset($ruleData['name']) ? Validation::sanitizeLogMessage($ruleData['name']) : '';
        $data['pattern'] = isset($ruleData['pattern']) ? trim($ruleData['pattern']) : '';
        $data['flags'] = isset($ruleData['flags']) ? $ruleData['flags'] : 'i';
        $data['severity'] = isset($ruleData['severity']) ? Validation::validateSeverityLevel((int)$ruleData['severity']) : 3;
        $data['action'] = isset($ruleData['action']) ? $ruleData['action'] : 'block';
        $data['message'] = isset($ruleData['message']) ? Validation::sanitizeLogMessage($ruleData['message']) : '';
        $data['category'] = isset($ruleData['category']) ? sanitize_key($ruleData['category']) : 'custom';
        $data['enabled'] = isset($ruleData['enabled']) ? (bool)$ruleData['enabled'] : true;
        $data['targets'] = isset($ruleData['targets']) && is_array($ruleData['targets']) ? $ruleData['targets'] : ['all'];
        $data['conditions'] = isset($ruleData['conditions']) && is_array($ruleData['conditions']) ? $ruleData['conditions'] : [];

        if (empty($data['name'])) {
            $errors[] = 'Rule name is required';
        }

        if (empty($data['pattern'])) {
            $errors[] = 'Rule pattern is required';
        } else {
            if (!$this->validateRegexPattern($data['pattern'], $data['flags'])) {
                $errors[] = 'Invalid regular expression pattern';
            }
        }

        if (!in_array($data['action'], ['block', 'monitor', 'challenge', 'allow', 'log'], true)) {
            $errors[] = 'Invalid action specified';
        }

        if (empty($data['message'])) {
            $data['message'] = "Custom rule triggered: {$data['name']}";
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'data' => $data
        ];
    }

    private function validateRegexPattern(string $pattern, string $flags): bool
    {
        $testPattern = '/' . str_replace('/', '\/', $pattern) . '/' . $flags;

        set_error_handler(function() { return true; });
        $isValid = @preg_match($testPattern, '') !== false;
        restore_error_handler();

        return $isValid;
    }

    private function evaluateRule(array $rule, array $requestData): array
    {
        $pattern = '/' . str_replace('/', '\/', $rule['pattern']) . '/' . $rule['flags'];

        foreach ($requestData as $source => $data) {
            if ($this->shouldCheckTarget($rule['targets'], $source)) {
                if (preg_match($pattern, $data, $matches)) {
                    return [
                        'triggered' => true,
                        'matched_data' => $matches[0] ?? '',
                        'source' => $source
                    ];
                }
            }
        }

        return ['triggered' => false];
    }

    private function shouldCheckTarget(array $targets, string $source): bool
    {
        return in_array('all', $targets) || in_array($source, $targets);
    }

    private function incrementHitCount(string $ruleId): void
    {
        $ruleIndex = $this->findRuleIndex($ruleId);
        if ($ruleIndex !== false) {
            $this->customRules[$ruleIndex]['hit_count']++;
            $this->customRules[$ruleIndex]['last_triggered'] = time();
            $this->saveCustomRules();
        }
    }

    private function saveCustomRules(): bool
    {
        return update_option($this->rulesOptionKey, $this->customRules);
    }

    private function loadCustomRules(): void
    {
        $savedRules = get_option($this->rulesOptionKey, []);
        $this->customRules = is_array($savedRules) ? $savedRules : [];
    }

    private function findRuleIndex(string $ruleId): int|false
    {
        foreach ($this->customRules as $index => $rule) {
            if ($rule['id'] === $ruleId) {
                return $index;
            }
        }
        return false;
    }

    private function logRuleAction(array $rule, string $action): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'waf_rule_' . $action,
            'severity' => 2,
            'ip_address' => IPUtils::getRealClientIP(),
            'message' => "WAF custom rule {$action}: {$rule['name']} ({$rule['id']})",
            'context' => [
                'rule_id' => $rule['id'],
                'rule_name' => $rule['name'],
                'action' => $action,
                'category' => $rule['category']
            ],
            'action_taken' => 'rule_' . $action
        ]);
    }
}

