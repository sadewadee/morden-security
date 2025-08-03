<?php

namespace MordenSecurity\Modules\WAF;

use MordenSecurity\Core\LoggerSQLite;

if (!defined('ABSPATH')) {
    exit;
}

class RulesetManager
{
    private LoggerSQLite $logger;
    private string $rulesetsPath;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->rulesetsPath = MS_PLUGIN_PATH . 'data/rulesets/';
    }

    public function syncRulesetsToDatabase(): int
    {
        $rulesets = glob($this->rulesetsPath . '*.json');
        $rulesAdded = 0;

        foreach ($rulesets as $rulesetFile) {
            $rulesetName = basename($rulesetFile, '.json');
            $content = file_get_contents($rulesetFile);
            $rulesetData = json_decode($content, true);

            if (!is_array($rulesetData) || empty($rulesetData['rules'])) {
                continue;
            }

            foreach ($rulesetData['rules'] as $rule) {
                if ($this->ruleExists($rule['id'])) {
                    continue;
                }

                $success = $this->insertRule($rule, $rulesetName);
                if ($success) {
                    $rulesAdded++;
                }
            }
        }

        return $rulesAdded;
    }

    private function ruleExists(string $ruleId): bool
    {
        $stmt = $this->logger->database->prepare('SELECT id FROM ms_waf_rules WHERE rule_id = :rule_id');
        $stmt->bindValue(':rule_id', $ruleId, SQLITE3_TEXT);
        $result = $stmt->execute();
        return $result->fetchArray() !== false;
    }

    private function insertRule(array $rule, string $rulesetName): bool
    {
        $stmt = $this->logger->database->prepare('
            INSERT INTO ms_waf_rules (rule_id, ruleset_name, name, description, pattern, threat_score, is_active, is_custom)
            VALUES (:rule_id, :ruleset_name, :name, :description, :pattern, :threat_score, :is_active, 0)
        ');

        $stmt->bindValue(':rule_id', $rule['id'], SQLITE3_TEXT);
        $stmt->bindValue(':ruleset_name', $rulesetName, SQLITE3_TEXT);
        $stmt->bindValue(':name', $rule['name'], SQLITE3_TEXT);
        $stmt->bindValue(':description', $rule['message'], SQLITE3_TEXT); // Using message as description
        $stmt->bindValue(':pattern', $rule['pattern'], SQLITE3_TEXT);
        $stmt->bindValue(':threat_score', $rule['severity'] ?? 3, SQLITE3_INTEGER);
        $stmt->bindValue(':is_active', $rule['enabled'] ?? 1, SQLITE3_INTEGER);

        $result = $stmt->execute();
        return $result !== false;
    }

    public function getActiveRules(): array
    {
        $stmt = $this->logger->database->prepare('SELECT * FROM ms_waf_rules WHERE is_active = 1');
        $result = $stmt->execute();
        $rules = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rules[] = $row;
        }
        return $rules;
    }
}