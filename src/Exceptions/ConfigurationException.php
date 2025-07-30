<?php

namespace MordenSecurity\Exceptions;

if (!defined('ABSPATH')) {
    exit;
}

class ConfigurationException extends SecurityException
{
    public function __construct(string $message = '', array $context = [], int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, 'CONFIGURATION_ERROR', $context, $code, $previous);
    }
}
