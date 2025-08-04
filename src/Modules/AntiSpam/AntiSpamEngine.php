<?php

namespace MordenSecurity\Modules\AntiSpam;

use MordenSecurity\Core\LoggerSQLite;

if (!defined('ABSPATH')) {
    exit;
}

class AntiSpamEngine
{
    private array $config;
    private LoggerSQLite $logger;
    private CommentAntiSpam $commentAntiSpam;
    private BehaviorTracker $behaviorTracker;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->loadConfig();
        $this->initializeModules();
        $this->initializeHooks();
    }

    private function loadConfig(): void
    {
        $this->config = [
            'protect_registration' => get_option('ms_protect_registration'),
            'protect_other_forms' => get_option('ms_protect_other_forms'),
            'form_protection_service' => get_option('ms_form_protection_service'),
            'recaptcha_site_key' => get_option('ms_recaptcha_site_key'),
            'recaptcha_secret_key' => get_option('ms_recaptcha_secret_key'),
            'turnstile_site_key' => get_option('ms_turnstile_site_key'),
            'turnstile_secret_key' => get_option('ms_turnstile_secret_key'),
        ];
    }

    private function initializeModules(): void
    {
        $this->commentAntiSpam = new CommentAntiSpam($this->logger);
        $this->behaviorTracker = new BehaviorTracker($this->logger);
    }

    private function initializeHooks(): void
    {
        // Hook for registration form protection
        if ($this->config['protect_registration']) {
            add_action('register_post', [$this, 'validateFormSubmission'], 10, 3);
        }

        // Generic hook for other forms (e.g., login, lost password)
        if ($this->config['protect_other_forms']) {
            add_action('wp_authenticate_user', [$this, 'validateFormSubmission'], 10, 1);
        }

        // Add CAPTCHA to forms if enabled
        if ($this->config['form_protection_service']) {
            add_action('login_form', [$this, 'displayCaptcha']);
            add_action('register_form', [$this, 'displayCaptcha']);
            add_action('comment_form_after_fields', [$this, 'displayCaptcha']);
        }
    }

    public function validateFormSubmission($userOrError)
    {
        // Behavior score check
        $ipAddress = \MordenSecurity\Utils\IPUtils::getRealClientIP();
        $behaviorScore = $this->behaviorTracker->getBehaviorScore($ipAddress);

        if ($behaviorScore > 70) { // Threshold can be made configurable
            $this->logger->logSecurityEvent([
                'event_type' => 'form_spam_behavior',
                'severity' => 3,
                'ip_address' => $ipAddress,
                'message' => 'High behavior score detected during form submission.',
                'context' => ['score' => $behaviorScore],
                'action_taken' => 'blocked'
            ]);
            return new \WP_Error('spam_detection', __('Your submission has been flagged as potential spam.', 'morden-security'));
        }

        // CAPTCHA validation
        if ($this->config['form_protection_service']) {
            $captchaValid = $this->validateCaptcha();
            if (!$captchaValid) {
                return new \WP_Error('captcha_invalid', __('Invalid CAPTCHA. Please try again.', 'morden-security'));
            }
        }

        return $userOrError;
    }

    public function displayCaptcha(): void
    {
        $service = $this->config['form_protection_service'];
        if ($service === 'recaptcha' && !empty($this->config['recaptcha_site_key'])) {
            echo '<div class="g-recaptcha" data-sitekey="' . esc_attr($this->config['recaptcha_site_key']) . '"></div>';
            wp_enqueue_script('recaptcha-api', 'https://www.google.com/recaptcha/api.js', [], null, true);
        } elseif ($service === 'turnstile' && !empty($this->config['turnstile_site_key'])) {
            echo '<div class="cf-turnstile" data-sitekey="' . esc_attr($this->config['turnstile_site_key']) . '"></div>';
            wp_enqueue_script('turnstile-api', 'https://challenges.cloudflare.com/turnstile/v0/api.js', [], null, true);
        }
    }

    private function validateCaptcha(): bool
    {
        $service = $this->config['form_protection_service'];
        $ipAddress = \MordenSecurity\Utils\IPUtils::getRealClientIP();

        if ($service === 'recaptcha') {
            $token = $_POST['g-recaptcha-response'] ?? '';
            $secretKey = $this->config['recaptcha_secret_key'];
            $url = 'https://www.google.com/recaptcha/api/siteverify';
            $data = ['secret' => $secretKey, 'response' => $token, 'remoteip' => $ipAddress];
        } elseif ($service === 'turnstile') {
            $token = $_POST['cf-turnstile-response'] ?? '';
            $secretKey = $this->config['turnstile_secret_key'];
            $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
            $data = ['secret' => $secretKey, 'response' => $token, 'remoteip' => $ipAddress];
        } else {
            return false;
        }

        if (empty($token)) return false;

        $response = wp_remote_post($url, ['body' => $data]);
        if (is_wp_error($response)) {
            return false;
        }

        $result = json_decode(wp_remote_retrieve_body($response), true);
        return $result['success'] ?? false;
    }
}
