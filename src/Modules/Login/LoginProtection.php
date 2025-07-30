<?php

namespace MordenSecurity\Modules\Login;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class LoginProtection
{
    private LoggerSQLite $logger;
    private RateLimiter $rateLimiter;
    private CaptchaManager $captchaManager;
    private array $config;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->rateLimiter = new RateLimiter($logger);
        $this->captchaManager = new CaptchaManager();
        $this->config = [
            'login_protection_enabled' => get_option('ms_login_protection_enabled', true),
            'max_login_attempts' => get_option('ms_max_login_attempts', 5),
            'lockout_duration' => get_option('ms_lockout_duration', 900),
            'enable_captcha_after' => get_option('ms_enable_captcha_after', 3),
            'strong_password_required' => get_option('ms_strong_password_required', true)
        ];

        $this->initializeHooks();
    }

    public function checkLoginAttempt(string $username): array
    {
        if (!$this->config['login_protection_enabled']) {
            return ['allowed' => true, 'reason' => 'protection_disabled'];
        }

        $ipAddress = IPUtils::getRealClientIP();

        $ipAttempts = $this->rateLimiter->getAttemptCount($ipAddress, 'login', 3600);
        $usernameAttempts = $this->rateLimiter->getAttemptCount($username, 'login', 3600);

        if ($ipAttempts >= $this->config['max_login_attempts']) {
            return [
                'allowed' => false,
                'reason' => 'ip_rate_limited',
                'lockout_until' => $this->rateLimiter->getLockoutTime($ipAddress, 'login')
            ];
        }

        if ($usernameAttempts >= $this->config['max_login_attempts']) {
            return [
                'allowed' => false,
                'reason' => 'username_rate_limited',
                'lockout_until' => $this->rateLimiter->getLockoutTime($username, 'login')
            ];
        }

        if ($ipAttempts >= $this->config['enable_captcha_after']) {
            return [
                'allowed' => true,
                'reason' => 'captcha_required',
                'requires_captcha' => true
            ];
        }

        return ['allowed' => true, 'reason' => 'allowed'];
    }

    public function handleFailedLogin(string $username, string $error): void
    {
        $ipAddress = IPUtils::getRealClientIP();

        $this->rateLimiter->recordAttempt($ipAddress, 'login');
        $this->rateLimiter->recordAttempt($username, 'login');

        $this->logger->logSecurityEvent([
            'event_type' => 'login_failed',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'message' => "Failed login attempt for user: {$username}",
            'context' => [
                'username' => $username,
                'error_code' => $error,
                'attempt_count' => $this->rateLimiter->getAttemptCount($ipAddress, 'login', 3600)
            ],
            'action_taken' => 'logged'
        ]);

        if ($this->shouldBlockUser($ipAddress, $username)) {
            $this->blockLoginAttempts($ipAddress, $username);
        }
    }

    public function handleSuccessfulLogin(string $username): void
    {
        $ipAddress = IPUtils::getRealClientIP();
        $user = get_user_by('login', $username);

        if ($user && user_can($user, 'administrator')) {
            $this->autoWhitelistAdmin($ipAddress, $username);
        }

        $this->logger->logSecurityEvent([
            'event_type' => 'login_success',
            'severity' => 1,
            'ip_address' => $ipAddress,
            'message' => "Successful login for user: {$username}",
            'context' => [
                'username' => $username,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'auto_whitelisted' => user_can($user, 'administrator')
            ],
            'action_taken' => 'login_allowed'
        ]);
    }

    private function autoWhitelistAdmin(string $ipAddress, string $username): void
    {
        $whitelistData = [
            'ip_address' => $ipAddress,
            'rule_type' => 'temp_whitelist',
            'block_duration' => 'temporary',
            'blocked_until' => time() + (24 * 3600), // 24 jam
            'reason' => "Auto-whitelist admin: {$username}",
            'threat_score' => 0,
            'block_source' => 'admin_login',
            'created_by' => get_user_by('login', $username)->ID,
            'escalation_count' => 0,
            'notes' => 'Temporary admin whitelist - 24 hours'
        ];

        $this->logger->addIPRule($whitelistData);

        // Log whitelist action
        $this->logger->logSecurityEvent([
            'event_type' => 'admin_auto_whitelisted',
            'severity' => 1,
            'ip_address' => $ipAddress,
            'message' => "Admin {$username} auto-whitelisted for 24 hours",
            'context' => [
                'username' => $username,
                'duration' => '24_hours',
                'whitelist_type' => 'admin_login'
            ],
            'action_taken' => 'ip_whitelisted'
        ]);
    }


    public function validatePassword(string $password, string $username): array
    {
        if (!$this->config['strong_password_required']) {
            return ['valid' => true];
        }

        $errors = [];

        if (strlen($password) < 8) {
            $errors[] = __('Password must be at least 8 characters long', 'morden-security');
        }

        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = __('Password must contain at least one uppercase letter', 'morden-security');
        }

        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = __('Password must contain at least one lowercase letter', 'morden-security');
        }

        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = __('Password must contain at least one number', 'morden-security');
        }

        if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
            $errors[] = __('Password must contain at least one special character', 'morden-security');
        }

        if (stripos($password, $username) !== false) {
            $errors[] = __('Password must not contain the username', 'morden-security');
        }

        $commonPasswords = ['password', '123456', 'admin', 'password123', 'welcome'];
        if (in_array(strtolower($password), $commonPasswords)) {
            $errors[] = __('Password is too common', 'morden-security');
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }

    public function addCaptchaToLoginForm(): void
    {
        $ipAddress = IPUtils::getRealClientIP();
        $attempts = $this->rateLimiter->getAttemptCount($ipAddress, 'login', 3600);

        if ($attempts >= $this->config['enable_captcha_after']) {
            echo $this->captchaManager->renderCaptcha();
        }
    }

    public function hideLoginErrors(string $error): string
    {
        if (get_option('ms_hide_login_errors', true)) {
            return __('Invalid login credentials', 'morden-security');
        }

        return $error;
    }

    private function initializeHooks(): void
    {
        add_action('wp_login_failed', [$this, 'handleFailedLogin']);
        add_action('wp_login', [$this, 'handleSuccessfulLogin'], 10, 1);
        add_action('login_form', [$this, 'addCaptchaToLoginForm']);
        add_filter('login_errors', [$this, 'hideLoginErrors']);
        add_action('authenticate', [$this, 'authenticateUser'], 30, 3);
    }

    public function authenticateUser($user, string $username, string $password)
    {
        if (empty($username) || empty($password)) {
            return $user;
        }

        $loginCheck = $this->checkLoginAttempt($username);

        if (!$loginCheck['allowed']) {
            return new WP_Error('login_blocked', $this->getBlockedMessage($loginCheck));
        }

        if (isset($loginCheck['requires_captcha'])) {
            $captchaValid = $this->captchaManager->validateCaptcha($_POST['ms_captcha'] ?? '');
            if (!$captchaValid) {
                return new WP_Error('captcha_failed', __('CAPTCHA validation failed', 'morden-security'));
            }
        }

        return $user;
    }

    private function shouldBlockUser(string $ipAddress, string $username): bool
    {
        $ipAttempts = $this->rateLimiter->getAttemptCount($ipAddress, 'login', 3600);
        $usernameAttempts = $this->rateLimiter->getAttemptCount($username, 'login', 3600);

        return $ipAttempts >= $this->config['max_login_attempts'] ||
               $usernameAttempts >= $this->config['max_login_attempts'];
    }

    private function blockLoginAttempts(string $ipAddress, string $username): void
    {
        $this->rateLimiter->setLockout($ipAddress, 'login', $this->config['lockout_duration']);
        $this->rateLimiter->setLockout($username, 'login', $this->config['lockout_duration']);

        $this->logger->logSecurityEvent([
            'event_type' => 'login_blocked',
            'severity' => 3,
            'ip_address' => $ipAddress,
            'message' => "Login blocked for IP: {$ipAddress} and username: {$username}",
            'context' => [
                'username' => $username,
                'lockout_duration' => $this->config['lockout_duration']
            ],
            'action_taken' => 'login_blocked'
        ]);
    }

    private function getBlockedMessage(array $loginCheck): string
    {
        $lockoutTime = $loginCheck['lockout_until'] ?? 0;
        $timeRemaining = $lockoutTime - time();

        if ($timeRemaining > 0) {
            $minutes = ceil($timeRemaining / 60);
            return sprintf(
                __('Too many failed login attempts. Please try again in %d minutes.', 'morden-security'),
                $minutes
            );
        }

        return __('Login temporarily blocked due to suspicious activity.', 'morden-security');
    }
}
