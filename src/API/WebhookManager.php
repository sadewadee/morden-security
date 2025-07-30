<?php

namespace MordenSecurity\API;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\Validation;

if (!defined('ABSPATH')) {
    exit;
}

class WebhookManager
{
    private LoggerSQLite $logger;
    private array $webhookUrls;
    private array $config;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->webhookUrls = get_option('ms_webhook_urls', []);
        $this->config = [
            'webhooks_enabled' => get_option('ms_webhooks_enabled', false),
            'retry_attempts' => get_option('ms_webhook_retry_attempts', 3),
            'timeout' => get_option('ms_webhook_timeout', 30)
        ];
    }

    public function sendWebhook(string $event, array $data): bool
    {
        if (!$this->config['webhooks_enabled'] || empty($this->webhookUrls)) {
            return false;
        }

        $payload = $this->buildPayload($event, $data);
        $success = false;

        foreach ($this->webhookUrls as $webhook) {
            if ($this->shouldSendToWebhook($webhook, $event)) {
                $result = $this->sendToWebhook($webhook, $payload);
                if ($result) {
                    $success = true;
                }
            }
        }

        return $success;
    }

    public function addWebhook(array $webhookData): bool
    {
        $webhook = [
            'id' => uniqid('webhook_'),
            'url' => Validation::sanitizeURL($webhookData['url']),
            'events' => $webhookData['events'] ?? [],
            'secret' => $webhookData['secret'] ?? '',
            'enabled' => $webhookData['enabled'] ?? true,
            'created_at' => time()
        ];

        if (empty($webhook['url'])) {
            return false;
        }

        $this->webhookUrls[] = $webhook;
        return update_option('ms_webhook_urls', $this->webhookUrls);
    }

    public function removeWebhook(string $webhookId): bool
    {
        $this->webhookUrls = array_filter(
            $this->webhookUrls,
            fn($webhook) => $webhook['id'] !== $webhookId
        );

        return update_option('ms_webhook_urls', array_values($this->webhookUrls));
    }

    public function testWebhook(string $webhookId): array
    {
        $webhook = $this->getWebhookById($webhookId);
        if (!$webhook) {
            return ['success' => false, 'message' => 'Webhook not found'];
        }

        $testPayload = $this->buildPayload('webhook_test', [
            'message' => 'This is a test webhook from Morden Security',
            'timestamp' => time(),
            'test' => true
        ]);

        $result = $this->sendToWebhook($webhook, $testPayload);

        return [
            'success' => $result,
            'message' => $result ? 'Webhook test successful' : 'Webhook test failed'
        ];
    }

    public function getWebhooks(): array
    {
        return $this->webhookUrls;
    }

    private function buildPayload(string $event, array $data): array
    {
        return [
            'event' => $event,
            'timestamp' => time(),
            'site_url' => get_site_url(),
            'plugin_version' => MS_PLUGIN_VERSION,
            'data' => $data
        ];
    }

    private function shouldSendToWebhook(array $webhook, string $event): bool
    {
        if (!$webhook['enabled']) {
            return false;
        }

        if (empty($webhook['events'])) {
            return true;
        }

        return in_array($event, $webhook['events']);
    }

    private function sendToWebhook(array $webhook, array $payload): bool
    {
        $attempts = 0;
        $maxAttempts = $this->config['retry_attempts'];

        while ($attempts < $maxAttempts) {
            $response = $this->makeHttpRequest($webhook, $payload);

            if ($response['success']) {
                $this->logWebhookSuccess($webhook, $payload);
                return true;
            }

            $attempts++;
            if ($attempts < $maxAttempts) {
                sleep(pow(2, $attempts));
            }
        }

        $this->logWebhookFailure($webhook, $payload, $response['error']);
        return false;
    }

    private function makeHttpRequest(array $webhook, array $payload): array
    {
        $headers = [
            'Content-Type' => 'application/json',
            'User-Agent' => 'Morden-Security/' . MS_PLUGIN_VERSION
        ];

        if (!empty($webhook['secret'])) {
            $signature = hash_hmac('sha256', json_encode($payload), $webhook['secret']);
            $headers['X-Signature'] = 'sha256=' . $signature;
        }

        $args = [
            'method' => 'POST',
            'headers' => $headers,
            'body' => json_encode($payload),
            'timeout' => $this->config['timeout'],
            'blocking' => true
        ];

        $response = wp_remote_request($webhook['url'], $args);

        if (is_wp_error($response)) {
            return ['success' => false, 'error' => $response->get_error_message()];
        }

        $statusCode = wp_remote_retrieve_response_code($response);

        if ($statusCode >= 200 && $statusCode < 300) {
            return ['success' => true];
        }

        return ['success' => false, 'error' => "HTTP {$statusCode}"];
    }

    private function logWebhookSuccess(array $webhook, array $payload): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'webhook_success',
            'severity' => 1,
            'ip_address' => '127.0.0.1',
            'message' => "Webhook sent successfully to {$webhook['url']}",
            'context' => [
                'webhook_id' => $webhook['id'],
                'webhook_url' => $webhook['url'],
                'event' => $payload['event']
            ],
            'action_taken' => 'webhook_sent'
        ]);
    }

    private function logWebhookFailure(array $webhook, array $payload, string $error): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'webhook_failure',
            'severity' => 2,
            'ip_address' => '127.0.0.1',
            'message' => "Failed to send webhook to {$webhook['url']}: {$error}",
            'context' => [
                'webhook_id' => $webhook['id'],
                'webhook_url' => $webhook['url'],
                'event' => $payload['event'],
                'error' => $error
            ],
            'action_taken' => 'webhook_failed'
        ]);
    }

    private function getWebhookById(string $webhookId): ?array
    {
        foreach ($this->webhookUrls as $webhook) {
            if ($webhook['id'] === $webhookId) {
                return $webhook;
            }
        }
        return null;
    }
}
