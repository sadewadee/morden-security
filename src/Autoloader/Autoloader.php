<?php

namespace MordenSecurity\Autoloader;

if (!defined('ABSPATH')) {
    exit;
}

class Autoloader
{
    private array $namespaces = [];
    private bool $registered = false;

    public function addNamespace(string $namespace, string $basePath): self
    {
        $namespace = trim($namespace, '\\') . '\\';
        $basePath = rtrim($basePath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        $this->namespaces[$namespace] = $basePath;

        return $this;
    }

    public function register(): bool
    {
        if ($this->registered) {
            return true;
        }

        $this->registered = spl_autoload_register([$this, 'loadClass']);
        return $this->registered;
    }

    public function unregister(): bool
    {
        if (!$this->registered) {
            return true;
        }

        $result = spl_autoload_unregister([$this, 'loadClass']);
        if ($result) {
            $this->registered = false;
        }

        return $result;
    }

    private function loadClass(string $className): bool
    {
        foreach ($this->namespaces as $namespace => $basePath) {
            if (strpos($className, $namespace) === 0) {
                $relativeClassName = substr($className, strlen($namespace));
                $filePath = $this->findFile($basePath, $relativeClassName);

                if ($filePath && is_readable($filePath)) {
                    require_once $filePath;
                    return true;
                }
            }
        }

        return false;
    }

    private function findFile(string $basePath, string $className): string
    {
        $fileName = $this->classNameToFileName($className);
        return $basePath . $fileName;
    }

    private function classNameToFileName(string $className): string
    {
        return str_replace('\\', DIRECTORY_SEPARATOR, $className) . '.php';
    }
}
