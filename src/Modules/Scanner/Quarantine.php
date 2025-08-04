<?php

namespace MordenSecurity\Modules\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

class Quarantine
{
    private string $quarantine_dir;

    public function __construct()
    {
        $upload_dir = wp_upload_dir();
        $this->quarantine_dir = $upload_dir['basedir'] . '/morden-security-quarantine/';
        if (!file_exists($this->quarantine_dir)) {
            wp_mkdir_p($this->quarantine_dir);
            // Add a .htaccess file for security
            $htaccess_content = "Options -Indexes\ndeny from all";
            file_put_contents($this->quarantine_dir . '.htaccess', $htaccess_content);
        }
    }

    public function quarantineFile(string $file_path): bool
    {
        $full_path = ABSPATH . $file_path;
        if (!file_exists($full_path) || is_dir($full_path)) {
            return false;
        }

        $destination = $this->quarantine_dir . basename($file_path) . '.' . time();

        // Use rename to move the file
        if (rename($full_path, $destination)) {
            // You might want to log this action
            return true;
        }

        return false;
    }

    public function restoreFile(string $quarantined_file, string $original_path): bool
    {
        $quarantined_path = $this->quarantine_dir . $quarantined_file;
        $destination_path = ABSPATH . $original_path;

        if (!file_exists($quarantined_path)) {
            return false;
        }

        // Ensure the destination directory exists
        $destination_dir = dirname($destination_path);
        if (!file_exists($destination_dir)) {
            wp_mkdir_p($destination_dir);
        }

        if (rename($quarantined_path, $destination_path)) {
            return true;
        }

        return false;
    }

    public function deleteQuarantinedFile(string $quarantined_file): bool
    {
        $quarantined_path = $this->quarantine_dir . $quarantined_file;
        if (file_exists($quarantined_path) && is_writable($quarantined_path)) {
            return unlink($quarantined_path);
        }
        return false;
    }

    public function getQuarantinedFiles(): array
    {
        $files = [];
        $items = scandir($this->quarantine_dir);
        foreach ($items as $item) {
            if ($item !== '.' && $item !== '..' && $item !== '.htaccess') {
                $files[] = [
                    'file_name' => $item,
                    'size' => filesize($this->quarantine_dir . $item),
                    'date' => filemtime($this->quarantine_dir . $item)
                ];
            }
        }
        return $files;
    }
}
