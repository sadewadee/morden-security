jQuery(document).ready(function($) {
    // Tab functionality
    $('.nav-tab').on('click', function(e) {
        e.preventDefault();

        var target = $(this).attr('href');

        $('.nav-tab').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');

        $('.tab-content').removeClass('active');
        $(target).addClass('active');
    });

    // Load security stats
    loadSecurityStats();

    // Security logs functionality
    if ($('#ms-logs-table').length > 0) {
        loadSecurityLogs();

        $('#ms-filter-logs').on('click', function() {
            loadSecurityLogs();
        });

        $('#ms-export-logs').on('click', function() {
            exportSecurityLogs();
        });
    }

    // Double-click functionality for description cells
    $(document).on('dblclick', '.ms-description-cell', function(e) {
        e.preventDefault();
        e.stopPropagation();

        var $cell = $(this);
        var isExpanded = $cell.hasClass('expanded');

        // Close all other expanded cells
        $('.ms-description-cell.expanded').removeClass('expanded');

        if (!isExpanded) {
            $cell.addClass('expanded');

            // Add click outside to close
            setTimeout(function() {
                $(document).on('click.description-close', function(e) {
                    if (!$cell.is(e.target) && $cell.has(e.target).length === 0) {
                        $cell.removeClass('expanded');
                        $(document).off('click.description-close');
                    }
                });
            }, 100);
        }
    });

    // Single click to show hint
    $(document).on('click', '.ms-description-cell:not(.expanded)', function(e) {
        e.preventDefault();
        var $cell = $(this);

        // Show temporary hint
        if (!$cell.find('.ms-temp-hint').length) {
            var $hint = $('<div class="ms-temp-hint" style="position: absolute; bottom: -25px; left: 0; background: #333; color: #fff; padding: 4px 8px; border-radius: 3px; font-size: 11px; white-space: nowrap; z-index: 100;">Double-click to expand</div>');
            $cell.append($hint);

            setTimeout(function() {
                $hint.fadeOut(300, function() {
                    $hint.remove();
                });
            }, 2000);
        }
    });

    // Block IP from logs functionality
    $(document).on('click', '.ms-block-ip-btn', function() {
        var ip = $(this).data('ip');
        var button = $(this);

        if (confirm(ms_ajax.confirm_block_ip)) {
            var reason = prompt('Enter reason for blocking this IP:', 'Suspicious activity detected in security logs');

            if (reason !== null && reason.trim() !== '') {
                $.ajax({
                    url: ms_ajax.ajax_url,
                    type: 'POST',
                    data: {
                        action: 'ms_block_ip_from_logs',
                        ip: ip,
                        reason: reason.trim(),
                        nonce: ms_ajax.nonce
                    },
                    beforeSend: function() {
                        button.prop('disabled', true).text(ms_ajax.blocking_ip);
                    },
                    success: function(response) {
                        if (response.success) {
                            button.removeClass('ms-block-ip-btn')
                                  .addClass('ms-unblock-ip-btn')
                                  .css('background', '#28a745')
                                  .text('Blocked')
                                  .prop('disabled', false);

                            showNotice(response.data, 'success');
                            loadSecurityStats();
                        } else {
                            alert('Error: ' + response.data);
                            button.prop('disabled', false).text(ms_ajax.block_ip);
                        }
                    },
                    error: function() {
                        alert('An error occurred while blocking the IP address.');
                        button.prop('disabled', false).text(ms_ajax.block_ip);
                    }
                });
            }
        }
    });

    // Unblock IP functionality
    $(document).on('click', '.ms-unblock-ip', function() {
        var ip = $(this).data('ip');
        var button = $(this);

        if (confirm(ms_ajax.confirm_unblock_ip)) {
            $.ajax({
                url: ms_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'ms_unblock_ip',
                    ip: ip,
                    nonce: ms_ajax.nonce
                },
                beforeSend: function() {
                    button.prop('disabled', true).text(ms_ajax.unblocking_ip);
                },
                success: function(response) {
                    if (response.success) {
                        button.closest('tr').fadeOut();
                        showNotice(response.data, 'success');
                    } else {
                        alert('Error: ' + response.data);
                        button.prop('disabled', false).text(ms_ajax.unblock);
                    }
                },
                error: function() {
                    alert('An error occurred while unblocking the IP address.');
                    button.prop('disabled', false).text(ms_ajax.unblock);
                }
            });
        }
    });

    // Integrity check functionality
    $('#ms-run-integrity-check').on('click', function() {
        var button = $(this);

        button.prop('disabled', true).text('Running integrity check...');

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_run_integrity_check',
                nonce: ms_ajax.nonce
            },
            timeout: 120000,
            success: function(response) {
                if (response.success) {
                    showNotice(response.data.message, 'success');
                    setTimeout(function() {
                        window.location.reload();
                    }, 2000);
                } else {
                    showNotice('Error: ' + response.data, 'error');
                    button.prop('disabled', false).text('Run Integrity Check Now');
                }
            },
            error: function() {
                showNotice('Integrity check failed. Please try again later.', 'error');
                button.prop('disabled', false).text('Run Integrity Check Now');
            }
        });
    });

    // Detailed report modal
    $('#ms-view-detailed-report').on('click', function() {
        $('#ms-detailed-report-modal').show();

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_get_detailed_report',
                nonce: ms_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    $('#ms-detailed-report-content').html(response.data.content);
                } else {
                    $('#ms-detailed-report-content').html('<p>Error loading detailed report.</p>');
                }
            },
            error: function() {
                $('#ms-detailed-report-content').html('<p>Error loading detailed report.</p>');
            }
        });
    });

    // Close modal
    $('.ms-modal-close').on('click', function() {
        $('#ms-detailed-report-modal').hide();
    });

    $(window).on('click', function(event) {
        if (event.target.id === 'ms-detailed-report-modal') {
            $('#ms-detailed-report-modal').hide();
        }
    });

    function loadSecurityStats() {
        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_get_security_stats',
                nonce: ms_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    $('#ms-login-attempts').text(response.data.login_attempts);
                    $('#ms-blocked-ips').text(response.data.blocked_ips);
                    $('#ms-security-events').text(response.data.security_events);
                }
            }
        });
    }

    function loadSecurityLogs(offset = 0) {
        var severity = $('#ms-severity-filter').val();
        var days = $('#ms-days-filter').val();
        var limit = $('#ms-limit-filter').val();

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_get_security_logs',
                severity: severity,
                days: days,
                limit: limit,
                offset: offset,
                nonce: ms_ajax.nonce
            },
            beforeSend: function() {
                $('#ms-logs-tbody').html('<tr><td colspan="8">Loading...</td></tr>');
            },
            success: function(response) {
                if (response.success) {
                    var logs = response.data.logs;
                    var total = response.data.total;
                    var html = '';

                    if (logs.length > 0) {
                        $.each(logs, function(index, log) {
                            html += '<tr>';
                            html += '<td>' + escapeHtml(log.created_at) + '</td>';
                            html += '<td>' + escapeHtml(log.event_type) + '</td>';
                            html += '<td>' + escapeHtml(log.ip_address) + '</td>';
                            html += '<td>' + escapeHtml(log.country || 'Unknown') + '</td>';
                            html += '<td>' + escapeHtml(log.path || '-') + '</td>';

                            // Description column with truncation and expand functionality
                            var description = escapeHtml(log.description);
                            var truncatedDesc = description.length > 50 ? description.substring(0, 50) + '...' : description;
                            var needsTruncation = description.length > 50;

                            html += '<td class="ms-description-cell' + (needsTruncation ? ' truncated' : '') + '" data-full-text="' + description + '">';
                            html += '<span class="truncated-text">' + truncatedDesc + '</span>';
                            html += '<span class="full-text" style="display: none;">' + description + '</span>';
                            if (needsTruncation) {
                                html += '<div class="ms-description-hint">Double-click to expand</div>';
                            }
                            html += '</td>';

                            html += '<td><span class="severity-' + escapeHtml(log.severity) + '">' + escapeHtml(log.severity) + '</span></td>';

                            // Action column
                            html += '<td>';
                            if (log.is_blocked == 1) {
                                html += '<span style="color: #28a745; font-weight: bold;">Blocked</span>';
                            } else if (log.ip_address && log.ip_address !== '127.0.0.1' && log.ip_address !== '::1') {
                                html += '<button class="ms-block-ip-btn" data-ip="' + escapeHtml(log.ip_address) + '">' + ms_ajax.block_ip + '</button>';
                            } else {
                                html += '-';
                            }
                            html += '</td>';

                            html += '</tr>';
                        });
                    } else {
                        html = '<tr><td colspan="8">No logs found</td></tr>';
                    }

                    $('#ms-logs-tbody').html(html);
                    updatePagination(total, limit, offset);
                }
            },
            error: function() {
                $('#ms-logs-tbody').html('<tr><td colspan="8">Error loading logs</td></tr>');
            }
        });
    }

    function updatePagination(total, limit, offset) {
        var totalPages = Math.ceil(total / limit);
        var currentPage = Math.floor(offset / limit) + 1;
        var html = '';

        if (totalPages > 1) {
            html += '<div class="tablenav-pages">';
            html += '<span class="displaying-num">' + total + ' items</span>';
            html += '<span class="pagination-links">';

            if (currentPage > 1) {
                html += '<a class="prev-page button" data-offset="' + ((currentPage - 2) * limit) + '">‹</a>';
            }

            for (var i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
                if (i === currentPage) {
                    html += '<span class="paging-input"><span class="tablenav-paging-text">' + i + ' of ' + totalPages + '</span></span>';
                } else {
                    html += '<a class="page-numbers button" data-offset="' + ((i - 1) * limit) + '">' + i + '</a>';
                }
            }

            if (currentPage < totalPages) {
                html += '<a class="next-page button" data-offset="' + (currentPage * limit) + '">›</a>';
            }

            html += '</span>';
            html += '</div>';
        }

        $('#ms-logs-pagination').html(html);

        $('#ms-logs-pagination a').on('click', function(e) {
            e.preventDefault();
            var offset = $(this).data('offset');
            loadSecurityLogs(offset);
        });
    }

    function exportSecurityLogs() {
        var severity = $('#ms-severity-filter').val();
        var days = $('#ms-days-filter').val();
        var limit = $('#ms-limit-filter').val();

        var params = new URLSearchParams({
            action: 'ms_export_security_logs',
            severity: severity,
            days: days,
            limit: limit,
            nonce: ms_ajax.nonce
        });

        window.open(ms_ajax.ajax_url + '?' + params.toString());
    }

    function showNotice(message, type) {
        var noticeClass = type === 'success' ? 'notice-success' : 'notice-error';
        var notice = '<div class="notice ' + noticeClass + ' is-dismissible"><p>' + escapeHtml(message) + '</p></div>';

        $('.wrap h1').after(notice);

        setTimeout(function() {
            $('.notice').fadeOut();
        }, 5000);
    }

    function escapeHtml(text) {
        if (!text) return '';
        var map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.toString().replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    $('#custom_login_url').on('input', function() {
        var newUrl = $(this).val() || 'secure-login';
        $('#login-url-preview').text(newUrl);
    });

    $('#ms-change-db-prefix').on('click', function() {
        var button = $(this);
        var newPrefix = $('#new_db_prefix').val();

        if (!newPrefix) {
            alert('Please enter a new database prefix.');
            return;
        }

        if (!confirm('Are you sure you want to change the database prefix? This will modify your database and wp-config.php file. Make sure you have a backup!')) {
            return;
        }

        button.prop('disabled', true).text('Changing prefix...');

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_change_db_prefix',
                new_prefix: newPrefix,
                nonce: ms_ajax.nonce
            },
            timeout: 60000,
            success: function(response) {
                if (response.success) {
                    alert(response.data + ' You will need to log in again.');
                    window.location.reload();
                } else {
                    alert('Error: ' + response.data);
                    button.prop('disabled', false).text('Change Database Prefix');
                }
            },
            error: function() {
                alert('Request failed. Please try again.');
                button.prop('disabled', false).text('Change Database Prefix');
            }
        });
    });

    $('#ms-check-permissions').on('click', function() {
        var button = $(this);

        button.prop('disabled', true).text('Checking permissions...');

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_check_permissions',
                nonce: ms_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    displayPermissionResults(response.data);
                    button.prop('disabled', false).text('Check File Permissions');
                } else {
                    alert('Error: ' + response.data);
                    button.prop('disabled', false).text('Check File Permissions');
                }
            },
            error: function() {
                alert('Request failed. Please try again.');
                button.prop('disabled', false).text('Check File Permissions');
            }
        });
    });

    $('#ms-fix-permissions').on('click', function() {
        var button = $(this);

        if (!confirm('Are you sure you want to fix file permissions? This will change file/folder permissions to recommended values.')) {
            return;
        }

        button.prop('disabled', true).text('Fixing permissions...');

        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_fix_permissions',
                nonce: ms_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    alert(response.data.message);
                    $('#ms-check-permissions').click();
                    button.prop('disabled', false).text('Fix Permissions');
                } else {
                    alert('Error: ' + response.data);
                    button.prop('disabled', false).text('Fix Permissions');
                }
            },
            error: function() {
                alert('Request failed. Please try again.');
                button.prop('disabled', false).text('Fix Permissions');
            }
        });
    });

    function displayPermissionResults(data) {
        var html = '';

        if (data.issues.length === 0) {
            html = '<div style="color: #46b450; font-weight: bold;">✓ All file permissions are secure!</div>';
            $('#ms-fix-permissions').hide();
        } else {
            html = '<div style="color: #d63638; margin-bottom: 10px;"><strong>Found ' + data.issues.length + ' permission issues:</strong></div>';
            html += '<table class="wp-list-table widefat fixed striped" style="margin-top: 10px;">';
            html += '<thead><tr><th>File/Folder</th><th>Current</th><th>Recommended</th><th>Type</th><th>Status</th></tr></thead>';
            html += '<tbody>';

            data.issues.forEach(function(issue) {
                var statusColor = issue.dangerous ? '#d63638' : '#ffb900';
                var statusText = issue.dangerous ? 'DANGEROUS' : 'Insecure';

                html += '<tr>';
                html += '<td><code>' + escapeHtml(issue.path) + '</code></td>';
                html += '<td><span style="color: ' + statusColor + ';">' + issue.current + '</span></td>';
                html += '<td><span style="color: #46b450;">' + issue.recommended + '</span></td>';
                html += '<td>' + issue.type + '</td>';
                html += '<td><span style="color: ' + statusColor + '; font-weight: bold;">' + statusText + '</span></td>';
                html += '</tr>';
            });

            html += '</tbody></table>';
            $('#ms-fix-permissions').show();
        }

        html += '<div style="margin-top: 10px; color: #666;"><strong>Summary:</strong> ' + data.secure_count + ' of ' + data.total_checked + ' items are secure.</div>';

        $('#ms-permissions-content').html(html);
        $('#ms-permissions-result').show();
    }

    function loadFirewallStats() {
        $.ajax({
            url: ms_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ms_get_firewall_stats',
                nonce: ms_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    $('#blocks-today').text(response.data.blocks_today || 0);
                    $('#blocks-week').text(response.data.blocks_week || 0);
                }
            }
        });
    }

    // Load firewall stats on page load
    if ($('#ms-firewall-stats').length > 0) {
        loadFirewallStats();

        // Refresh stats every 60 seconds
        setInterval(loadFirewallStats, 60000);
    }


    // Refresh stats every 30 seconds
    setInterval(loadSecurityStats, 30000);

    // Auto-refresh logs every 60 seconds if on logs page
    if ($('#ms-logs-table').length > 0) {
        setInterval(function() {
            loadSecurityLogs();
        }, 60000);
    }
});
