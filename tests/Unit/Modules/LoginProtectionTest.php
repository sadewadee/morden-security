<?php

namespace MordenSecurity\Tests\Unit\Modules;

use PHPUnit\Framework\TestCase;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Modules\Login\LoginProtection;
use MordenSecurity\Modules\Login\RateLimiter;
use MordenSecurity\Modules\Login\CaptchaManager;

class LoginProtectionTest extends TestCase
{
    private $logger;
    private $loginProtection;

    protected function setUp(): void
    {
        $this->logger = $this->createMock(LoggerSQLite::class);
        $this->loginProtection = new LoginProtection($this->logger);

        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_SERVER['HTTP_USER_AGENT'] = 'Test User Agent';
    }

    protected function tearDown(): void
    {
        unset($_SERVER['REMOTE_ADDR']);
        unset($_SERVER['HTTP_USER_AGENT']);
    }

    public function testCheckLoginAttemptAllowsWhenProtectionDisabled(): void
    {
        update_option('ms_login_protection_enabled', false);

        $loginProtection = new LoginProtection($this->logger);
        $result = $loginProtection->checkLoginAttempt('testuser');

        $this->assertTrue($result['allowed']);
        $this->assertEquals('protection_disabled', $result['reason']);
    }

    public function testCheckLoginAttemptAllowsValidUser(): void
    {
        update_option('ms_login_protection_enabled', true);
        update_option('ms_max_login_attempts', 5);

        $result = $this->loginProtection->checkLoginAttempt('validuser');

        $this->assertTrue($result['allowed']);
        $this->assertEquals('allowed', $result['reason']);
    }

    public function testHandleFailedLoginLogsEvent(): void
    {
        $this->logger->expects($this->once())
                    ->method('logSecurityEvent')
                    ->with($this->callback(function($event) {
                        return $event['event_type'] === 'login_failed' &&
                               $event['severity'] === 2 &&
                               strpos($event['message'], 'Failed login attempt') !== false;
                    }));

        $this->loginProtection->handleFailedLogin('testuser', 'invalid_username');
    }

    public function testHandleSuccessfulLoginLogsEvent(): void
    {
        $this->logger->expects($this->once())
                    ->method('logSecurityEvent')
                    ->with($this->callback(function($event) {
                        return $event['event_type'] === 'login_success' &&
                               $event['severity'] === 1 &&
                               strpos($event['message'], 'Successful login') !== false;
                    }));

        $this->loginProtection->handleSuccessfulLogin('testuser');
    }

    public function testValidatePasswordAcceptsStrongPassword(): void
    {
        update_option('ms_strong_password_required', true);

        $result = $this->loginProtection->validatePassword('StrongP@ssw0rd123', 'testuser');

        $this->assertTrue($result['valid']);
        $this->assertEmpty($result['errors'] ?? []);
    }

    public function testValidatePasswordRejectsWeakPassword(): void
    {
        update_option('ms_strong_password_required', true);

        $result = $this->loginProtection->validatePassword('weak', 'testuser');

        $this->assertFalse($result['valid']);
        $this->assertNotEmpty($result['errors']);
        $this->assertContains('Password must be at least 8 characters long', $result['errors']);
    }

    public function testValidatePasswordRejectsPasswordWithUsername(): void
    {
        update_option('ms_strong_password_required', true);

        $result = $this->loginProtection->validatePassword('TestUser123!', 'testuser');

        $this->assertFalse($result['valid']);
        $this->assertContains('Password must not contain the username', $result['errors']);
    }

    public function testValidatePasswordRejectsCommonPasswords(): void
    {
        update_option('ms_strong_password_required', true);

        $result = $this->loginProtection->validatePassword('password', 'testuser');

        $this->assertFalse($result['valid']);
        $this->assertContains('Password is too common', $result['errors']);
    }

    public function testValidatePasswordRequiresUppercase(): void
    {
        update_option('ms_strong_password_required', true);

        $result = $this->loginProtection->validatePassword('lowercase123!', 'testuser');

        $this->assertFalse($result['valid']);
        $this->assertContains('Password must contain at least one uppercase letter', $result['errors']);
    }

    public function testValidatePasswordRequiresLowercase(): void
    {
        update_option('ms_strong_password_required', true);

        $result = $this->loginProtection->validatePassword('UPPERCASE123!', 'testuser');

        $this->assertFalse($result['valid']);
        $this->assertContains('Password must contain at least one lowercase letter', $result['errors']);
    }

    public function testValidatePasswordRequiresNumber(): void
    {
        update_option('ms_strong_password_required', true);

        $result = $this->loginProtection->validatePassword('NoNumbers!', 'testuser');

        $this->assertFalse($result['valid']);
        $this->assertContains('Password must contain at least one number', $result['errors']);
    }

    public function testValidatePasswordRequiresSpecialCharacter(): void
    {
        update_option('ms_strong_password_required', true);

        $result = $this->loginProtection->validatePassword('NoSpecialChars123', 'testuser');

        $this->assertFalse($result['valid']);
        $this->assertContains('Password must contain at least one special character', $result['errors']);
    }

    public function testHideLoginErrorsHidesSpecificErrors(): void
    {
        update_option('ms_hide_login_errors', true);

        $result = $this->loginProtection->hideLoginErrors('Invalid username or password.');

        $this->assertEquals('Invalid login credentials', $result);
    }

    public function testHideLoginErrorsPassesThroughWhenDisabled(): void
    {
        update_option('ms_hide_login_errors', false);

        $originalError = 'Invalid username or password.';
        $result = $this->loginProtection->hideLoginErrors($originalError);

        $this->assertEquals($originalError, $result);
    }
}
