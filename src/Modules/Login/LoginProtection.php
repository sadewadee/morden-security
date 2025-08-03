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
    private CaptchaManager $captchaManager;
    private array $config;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->captchaManager = new CaptchaManager();
        $this->config = [
            'login_protection_enabled' => get_option('ms_login_protection_enabled', true),
            'max_login_attempts' => get_option('ms_max_login_attempts', 5),
            'lockout_duration' => get_option('ms_lockout_duration', 900), // 15 menit
            'enable_captcha_after' => get_option('ms_enable_captcha_after', 3),
            'strong_password_required' => get_option('ms_strong_password_required', true)
        ];

        $this->initializeHooks();
    }

    public function handleFailedLogin(string $username): void
    {
        if (!$this->config['login_protection_enabled']) {
            return;
        }

        $ipAddress = IPUtils::getRealClientIP();

        // Catat upaya gagal di tabel ringkasan
        $this->logger->recordFailedAttempt($ipAddress);

        // Dapatkan jumlah upaya gagal saat ini
        $attempts = $this->logger->getFailedAttempts($ipAddress)['attempts'] ?? 1;

        // Catat event ke log utama (lengkap)
        $this->logger->logSecurityEvent([
            'event_type' => 'login_failed',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'message' => "Failed login attempt for user: {$username} (Attempt #{$attempts})",
            'context' => ['username' => $username],
            'action_taken' => 'logged'
        ]);

        // Periksa apakah IP harus diblokir
        if ($attempts >= $this->config['max_login_attempts']) {
            $this->blockIP($ipAddress, $username, $attempts);
        }
    }

    private function blockIP(string $ipAddress, string $username, int $attempts): void
    {
        $this->logger->addIPRule([
            'ip_address' => $ipAddress,
            'rule_type' => 'blacklist',
            'block_duration' => 'temporary',
            'blocked_until' => time() + $this->config['lockout_duration'],
            'reason' => "Exceeded max login attempts ({$attempts}) as user '{$username}'",
            'block_source' => 'brute_force_protection'
        ]);

        // Hapus catatan dari tabel ringkasan setelah diblokir
        $this->logger->clearFailedAttempts($ipAddress);

        // Catat event pemblokiran
        $this->logger->logSecurityEvent([
            'event_type' => 'user_locked_out',
            'severity' => 3,
            'ip_address' => $ipAddress,
            'message' => "IP {$ipAddress} locked out for brute force attempts.",
            'context' => ['username' => $username, 'lockout_duration' => $this->config['lockout_duration']],
            'action_taken' => 'ip_blocked'
        ]);
    }

    public function handleSuccessfulLogin(string $username): void
    {
        $ipAddress = IPUtils::getRealClientIP();
        // Hapus catatan kegagalan sebelumnya dari IP ini setelah login berhasil
        $this->logger->clearFailedAttempts($ipAddress);

        $this->logger->logSecurityEvent([
            'event_type' => 'login_success',
            'severity' => 1,
            'ip_address' => $ipAddress,
            'message' => "Successful login for user: {$username}",
            'context' => ['username' => $username],
            'action_taken' => 'login_allowed'
        ]);
    }

    private function initializeHooks(): void
    {
        add_action('wp_login_failed', [$this, 'handleFailedLogin'], 10, 1);
        add_action('wp_login', [$this, 'handleSuccessfulLogin'], 10, 1);
        // Hook lainnya tetap sama...
    }

    // Metode lain seperti addCaptchaToLoginForm, hideLoginErrors, dll. tetap ada
    // tetapi sekarang dapat menggunakan getFailedAttempts untuk logika mereka.
}
