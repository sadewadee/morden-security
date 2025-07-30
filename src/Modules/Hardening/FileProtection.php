<?php

namespace MordenSecurity\Modules\Hardening;

if (!defined('ABSPATH')) {
    exit;
}

class FileProtection
{
    private array $protectedFiles;

    public function __construct()
    {
        $this->protectedFiles = [
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            ABSPATH . '.env',
            ABSPATH . 'composer.json'
        ];
    }

    public function enforceFilePermissions(): void
    {
        foreach ($this->protectedFiles as $filePath) {
            if (file_exists($filePath)) {
                $this->setFilePermissions($filePath, 0440);
            }
        }
    }

    private function setFilePermissions(string $filePath, int $permissions): void
    {
        $currentPerms = substr(sprintf('%o', fileperms($filePath)), -4);
        if ($currentPerms !== sprintf('%04o', $permissions)) {
            @chmod($filePath, $permissions);
        }
    }
}
