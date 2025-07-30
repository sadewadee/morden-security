<?php

namespace MordenSecurity\Modules\AntiSpam;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class CommentAntiSpam
{
    private LoggerSQLite $logger;
    private array $config;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->config = [
            'anti_spam_enabled' => get_option('ms_anti_spam_enabled', true),
            'spam_keywords' => get_option('ms_spam_keywords', ['viagra', 'casino', 'loan', 'free money']),
            'ip_blacklist_threshold' => get_option('ms_spam_ip_threshold', 3)
        ];

        $this->initializeHooks();
    }

    private function initializeHooks(): void
    {
        add_filter('preprocess_comment', [$this, 'checkCommentSpam'], 1);
    }

    public function checkCommentSpam(array $comment): array
    {
        if (!$this->config['anti_spam_enabled']) {
            return $comment;
        }

        $content = strtolower($comment['comment_content'] ?? '');
        foreach ($this->config['spam_keywords'] as $keyword) {
            if (strpos($content, strtolower($keyword)) !== false) {
                $this->flagSpam($comment, $keyword);
                wp_die(__('Your comment was flagged as spam.', 'morden-security'));
            }
        }

        $ipAddress = IPUtils::getRealClientIP();
        $spamCount = $this->logger->getIPThreatScore($ipAddress, 86400);

        if ($spamCount >= $this->config['ip_blacklist_threshold']) {
            $this->flagSpam($comment, 'ip_blacklist');
            wp_die(__('Too many spam attempts from your IP.', 'morden-security'));
        }

        return $comment;
    }

    private function flagSpam(array $comment, string $reason): void
    {
        $ipAddress = IPUtils::getRealClientIP();

        $this->logger->logSecurityEvent([
            'event_type' => 'comment_spam',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'message' => "Comment flagged as spam ({$reason})",
            'context' => ['comment' => $comment, 'reason' => $reason],
            'action_taken' => 'spam_blocked'
        ]);
    }
}
