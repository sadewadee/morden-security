/**
 * Morden Security Public JavaScript
 */

(function($) {
    'use strict';

    // Security Badge functionality
    function initSecurityBadge() {
        if ($('.ms-security-badge').length === 0) {
            $('body').append('<div class="ms-security-badge"><span class="ms-shield-icon">🛡️</span>Secured</div>');
        }

        // Hide badge after 5 seconds on mobile
        if (window.innerWidth <= 768) {
            setTimeout(function() {
                $('.ms-security-badge').fadeOut();
            }, 5000);
        }
    }

    // Login form enhancements
    function enhanceLoginForm() {
        if ($('body').hasClass('login')) {
            // Add loading state to login form
            $('#loginform').on('submit', function() {
                $(this).addClass('loading');
                $('.button-primary').prop('disabled', true).text('Signing in...');
            });

            // Add focus effects
            $('.login input[type="text"], .login input[type="password"], .login input[type="email"]').on('focus', function() {
                $(this).parent().addClass('focused');
            }).on('blur', function() {
                $(this).parent().removeClass('focused');
            });

            // Enhance error messages
            if ($('#login_error').length > 0) {
                $('#login_error').hide().fadeIn(500);
            }

            // Add keyboard navigation
            $('.login input').on('keydown', function(e) {
                if (e.key === 'Enter') {
                    var inputs = $('.login input:visible');
                    var currentIndex = inputs.index(this);
                    var nextInput = inputs.eq(currentIndex + 1);

                    if (nextInput.length > 0 && !nextInput.is(':submit')) {
                        e.preventDefault();
                        nextInput.focus();
                    }
                }
            });
        }
    }

    // Security status indicator
    function initSecurityStatus() {
        // Check if we should show security status
        if (typeof mordenSecurityConfig !== 'undefined' && mordenSecurityConfig.showStatus) {
            var statusLevel = mordenSecurityConfig.statusLevel || 'secure';
            var statusText = mordenSecurityConfig.statusText || 'Secure';

            var statusClass = 'ms-security-status';
            if (statusLevel === 'warning') {
                statusClass += ' warning';
            } else if (statusLevel === 'danger') {
                statusClass += ' danger';
            }

            $('body').append(
                '<div class="' + statusClass + '">' +
                '<span class="ms-status-icon"></span>' +
                statusText +
                '</div>'
            );
        }
    }

    // Real-time security monitoring
    function initSecurityMonitoring() {
        var suspiciousActivity = 0;
        var maxSuspiciousActivity = 5;

        // Monitor for suspicious JavaScript activity
        var originalConsoleLog = console.log;
        console.log = function() {
            // Check for common attack patterns in console
            var args = Array.prototype.slice.call(arguments);
            var logString = args.join(' ').toLowerCase();

            if (logString.includes('script') || logString.includes('eval') || logString.includes('document.write')) {
                suspiciousActivity++;
                if (suspiciousActivity >= maxSuspiciousActivity) {
                    reportSuspiciousActivity('console_injection');
                }
            }

            originalConsoleLog.apply(console, arguments);
        };

        // Monitor for DOM manipulation attempts
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach(function(node) {
                        if (node.nodeType === 1) { // Element node
                            var tagName = node.tagName.toLowerCase();
                            if (tagName === 'script' || tagName === 'iframe') {
                                var src = node.src || node.innerHTML;
                                if (src && !isWhitelistedSource(src)) {
                                    suspiciousActivity++;
                                    if (suspiciousActivity >= maxSuspiciousActivity) {
                                        reportSuspiciousActivity('dom_injection');
                                    }
                                }
                            }
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    // Check if source is whitelisted
    function isWhitelistedSource(src) {
        var whitelist = [
            window.location.origin,
            'https://challenges.cloudflare.com',
            'https://www.google.com',
            'https://www.gstatic.com'
        ];

        return whitelist.some(function(domain) {
            return src.indexOf(domain) === 0;
        });
    }

    // Report suspicious activity
    function reportSuspiciousActivity(type) {
        if (typeof mordenSecurityAjax !== 'undefined') {
            $.ajax({
                url: mordenSecurityAjax.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'ms_report_suspicious_activity',
                    type: type,
                    url: window.location.href,
                    userAgent: navigator.userAgent,
                    nonce: mordenSecurityAjax.nonce
                },
                success: function(response) {
                    if (response.success && response.data.block) {
                        window.location.reload();
                    }
                }
            });
        }
    }

    // Form protection
    function initFormProtection() {
        $('form').each(function() {
            var $form = $(this);
            var originalAction = $form.attr('action');

            // Add hidden security token
            if (!$form.find('input[name="ms_security_token"]').length) {
                $form.append('<input type="hidden" name="ms_security_token" value="' + generateSecurityToken() + '">');
            }

            // Monitor for form tampering
            $form.on('submit', function(e) {
                if (!validateFormSecurity($form)) {
                    e.preventDefault();
                    alert('Security validation failed. Please refresh the page and try again.');
                    return false;
                }
            });
        });
    }

    // Generate security token
    function generateSecurityToken() {
        return Math.random().toString(36).substr(2, 9);
    }

    // Validate form security
    function validateFormSecurity($form) {
        var action = $form.attr('action');
        var method = $form.attr('method') || 'GET';

        // Check for suspicious action URLs
        if (action && (action.includes('javascript:') || action.includes('data:'))) {
            return false;
        }

        // Check for suspicious input values
        var suspiciousPatterns = [
            /<script/i,
            /javascript:/i,
            /vbscript:/i,
            /on\w+\s*=/i
        ];

        var isValid = true;
        $form.find('input, textarea').each(function() {
            var value = $(this).val();
            suspiciousPatterns.forEach(function(pattern) {
                if (pattern.test(value)) {
                    isValid = false;
                    return false;
                }
            });
        });

        return isValid;
    }

    // Initialize clipboard protection
    function initClipboardProtection() {
        $(document).on('copy', function(e) {
            // Log clipboard access for security monitoring
            if (typeof mordenSecurityAjax !== 'undefined') {
                $.ajax({
                    url: mordenSecurityAjax.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'ms_log_clipboard_access',
                        nonce: mordenSecurityAjax.nonce
                    }
                });
            }
        });
    }

    // Initialize right-click protection (optional)
    function initRightClickProtection() {
        if (typeof mordenSecurityConfig !== 'undefined' && mordenSecurityConfig.disableRightClick) {
            $(document).on('contextmenu', function(e) {
                e.preventDefault();
                return false;
            });

            $(document).on('selectstart', function(e) {
                e.preventDefault();
                return false;
            });
        }
    }

    // Initialize developer tools detection
    function initDevToolsDetection() {
        var devtools = {
            open: false,
            orientation: null
        };

        var threshold = 160;

        setInterval(function() {
            if (window.outerHeight - window.innerHeight > threshold ||
                window.outerWidth - window.innerWidth > threshold) {
                if (!devtools.open) {
                    devtools.open = true;
                    if (typeof mordenSecurityAjax !== 'undefined') {
                        $.ajax({
                            url: mordenSecurityAjax.ajaxUrl,
                            type: 'POST',
                            data: {
                                action: 'ms_log_devtools_open',
                                nonce: mordenSecurityAjax.nonce
                            }
                        });
                    }
                }
            } else {
                devtools.open = false;
            }
        }, 500);
    }

    // Initialize on document ready
    $(document).ready(function() {
        initSecurityBadge();
        enhanceLoginForm();
        initSecurityStatus();
        initSecurityMonitoring();
        initFormProtection();
        initClipboardProtection();
        initRightClickProtection();
        initDevToolsDetection();
    });

    // Initialize on window load
    $(window).on('load', function() {
        // Additional initialization after page load
        setTimeout(function() {
            if ($('.ms-security-badge').length > 0) {
                $('.ms-security-badge').addClass('loaded');
            }
        }, 1000);
    });

})(jQuery);
