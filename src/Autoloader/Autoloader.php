<?php

namespace MordenSecurity\Autoloader;

if (!defined('ABSPATH')) {
    exit;
}

class Autoloader
{
    /**
     * Register the autoloader
     *
     * @return void
     */
    public static function register(): void
    {
        spl_autoload_register([self::class, 'autoload']);
    }

    /**
     * Autoload classes following PSR-4 standard
     *
     * @param string $class The fully-qualified class name
     * @return void
     */
    public static function autoload(string $class): void
    {
        // Project-specific namespace prefix
        $prefix = 'MordenSecurity\\';

        // Base directory for the namespace prefix
        $baseDir = MS_PLUGIN_PATH . 'src/';

        // Does the class use the namespace prefix?
        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            // No, move to the next registered autoloader
            return;
        }

        // Get the relative class name
        $relativeClass = substr($class, $len);

        // Replace the namespace prefix with the base directory, replace namespace
        // separators with directory separators in the relative class name, append
        // with .php
        $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

        // If the file exists, require it
        if (file_exists($file)) {
            require_once $file;
        }
    }

    /**
     * Unregister the autoloader
     *
     * @return bool True on success, false on failure
     */
    public static function unregister(): bool
    {
        return spl_autoload_unregister([self::class, 'autoload']);
    }

    /**
     * Check if a class can be autoloaded
     *
     * @param string $class The fully-qualified class name
     * @return bool True if class can be loaded, false otherwise
     */
    public static function canAutoload(string $class): bool
    {
        $prefix = 'MordenSecurity\\';
        $baseDir = MS_PLUGIN_PATH . 'src/';

        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            return false;
        }

        $relativeClass = substr($class, $len);
        $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

        return file_exists($file);
    }

    /**
     * Get all loadable classes in the namespace
     *
     * @return array Array of class names that can be autoloaded
     */
    public static function getLoadableClasses(): array
    {
        $classes = [];
        $baseDir = MS_PLUGIN_PATH . 'src/';

        if (!is_dir($baseDir)) {
            return $classes;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($baseDir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            if ($file->getExtension() === 'php') {
                $relativePath = str_replace([$baseDir, '.php', '/'], ['', '', '\\'], $file->getPathname());
                $className = 'MordenSecurity\\' . $relativePath;
                $classes[] = $className;
            }
        }

        return $classes;
    }

    /**
     * Preload critical classes for performance
     *
     * @return void
     */
    public static function preloadCriticalClasses(): void
    {
        $criticalClasses = [
            'MordenSecurity\\Core\\SecurityCore',
            'MordenSecurity\\Core\\LoggerSQLite',
            'MordenSecurity\\Core\\BotDetection',
            'MordenSecurity\\Core\\Firewall',
            'MordenSecurity\\Utils\\IPUtils',
            'MordenSecurity\\Utils\\Validation'
        ];

        foreach ($criticalClasses as $class) {
            if (self::canAutoload($class)) {
                self::autoload($class);
            }
        }
    }

    /**
     * Debug method to trace autoload attempts
     *
     * @param string $class The class being loaded
     * @return void
     */
    public static function debugAutoload(string $class): void
    {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log("MS Autoloader: Attempting to load class: {$class}");

            if (self::canAutoload($class)) {
                error_log("MS Autoloader: ✓ Can load {$class}");
            } else {
                error_log("MS Autoloader: ✗ Cannot load {$class}");
            }
        }
    }
}
