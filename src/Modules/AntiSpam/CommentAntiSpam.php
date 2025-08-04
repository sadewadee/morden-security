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
        $this->loadConfig();
        $this->initializeHooks();
    }

    private function loadConfig(): void
    {
        $this->config = [
            'protect_comment_form' => get_option('ms_protect_comment', true),
            'disable_for_logged_in' => get_option('ms_disable_for_logged_in', true),
            'spam_action' => get_option('ms_spam_action', 'deny'),
            'trash_days' => get_option('ms_trash_days', 7),
            'spam_keywords' => get_option('ms_spam_keywords', ['viagra', 'casino', 'loan', 'free money']),
            'ip_blacklist_threshold' => get_option('ms_spam_ip_threshold', 3)
        ];
    }

    private function initializeHooks(): void
    {
        if ($this->config['protect_comment_form']) {
            add_filter('preprocess_comment', [$this, 'checkCommentSpam'], 1);
        }
    }

    public function checkCommentSpam(array $commentdata): array
    {
        if ($this->config['disable_for_logged_in'] && is_user_logged_in()) {
            return $commentdata;
        }

        $isSpam = false;
        $spamReason = '';

        // Keyword check
        $content = strtolower($commentdata['comment_content'] ?? '');
        foreach ($this->config['spam_keywords'] as $keyword) {
            if (strpos($content, strtolower($keyword)) !== false) {
                $isSpam = true;
                $spamReason = "keyword: {$keyword}";
                break;
            }
        }

        // IP reputation check
        if (!$isSpam) {
            $ipAddress = IPUtils::getRealClientIP();
            $spamCount = $this->logger->getIPThreatScore($ipAddress, 86400);
            if ($spamCount >= $this->config['ip_blacklist_threshold']) {
                $isSpam = true;
                $spamReason = 'ip_reputation';
            }
        }

        if ($isSpam) {
            $this->flagSpam($commentdata, $spamReason);

            if ($this->config['spam_action'] === 'trash') {
                add_filter('pre_comment_approved', function () {
                    return 'trash';
                }, 99, 2);
            } else {
                wp_die(__('Your comment was flagged as spam.', 'morden-security'), __('Comment Spam Error', 'morden-security'), ['response' => 403]);
            }
        }

        return $commentdata;
    }

    private function flagSpam(array $comment, string $reason): void
    {
        $ipAddress = IPUtils::getRealClientIP();
        $action = $this->config['spam_action'] === 'trash' ? 'comment_trashed' : 'comment_denied';

        $this->logger->logSecurityEvent([
            'event_type' => 'comment_spam',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'message' => "Comment flagged as spam ({$reason})",
            'context' => ['comment' => $comment, 'reason' => $reason],
            'action_taken' => $action
        ]);
    }
}
