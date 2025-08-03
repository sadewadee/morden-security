<?php

namespace MordenSecurity\Modules\WAF;

use MordenSecurity\Core\LoggerSQLite;

class WAFRules {
    private LoggerSQLite $logger;
    private array $activeRules;

    public function __construct(LoggerSQLite $logger) {
        $this->logger = $logger;
        $this->loadActiveRules();
    }

    public function evaluateRequest(array $requestData): array {
        $violations = [];

        foreach ($this->activeRules as $rule) {
            $result = $this->evaluateRule($rule, $requestData);
            if ($result['triggered']) {
                $violations[] = [
                    'rule_db_id' => $rule['id'],
                    'rule_id' => $rule['rule_id'],
                    'rule_name' => $rule['name'],
                    'threat_score' => $rule['threat_score'],
                    'message' => $rule['description'],
                    'matched_data' => $result['matched_data'],
                    'source_field' => $result['source'],
                    'action' => 'block'
                ];
            }
        }

        usort($violations, fn($a, $b) => $b['threat_score'] <=> $a['threat_score']);

        return $violations;
    }

    private function loadActiveRules(): void {
        $this->activeRules = [];
        $stmt = $this->logger->database->prepare('SELECT * FROM ms_waf_rules WHERE is_active = 1');
        $result = $stmt->execute();
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $this->activeRules[] = $row;
        }
    }

    private function evaluateRule(array $rule, array $requestData): array {
        $pattern = $rule['pattern'];

        foreach ($requestData as $source => $data) {
            if (is_string($data) && $this->matchesPattern($pattern, $data)) {
                return [
                    'triggered' => true,
                    'matched_data' => substr($data, 0, 255),
                    'source' => $source
                ];
            }
        }

        return ['triggered' => false];
    }

    private function matchesPattern(string $pattern, string $data): bool {
        set_error_handler(function() { /* error */ });
        $result = @preg_match('/' . $pattern . '/', $data);
        restore_error_handler();

        return $result === 1;
    }

    public function getActiveRulesCount(): int {
        return count($this->activeRules);
    }
}