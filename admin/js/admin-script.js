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

    // Unblock IP functionality
    $(document).on('click', '.ms-unblock-ip', function() {
        var ip = $(this).data('ip');
        var button = $(this);

        if (confirm('Are you sure you want to unblock this IP address?')) {
            $.ajax({
                url: ms_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'ms_unblock_ip',
                    ip: ip,
                    nonce: ms_ajax.nonce
                },
                beforeSend: function() {
                    button.prop('disabled', true).text('Unblocking...');
                },
                success: function(response) {
                    if (response.success) {
                        button.closest('tr').fadeOut();
                        alert(response.data);
                    } else {
                        alert('Error: ' + response.data);
                        button.prop('disabled', false).text('Unblock');
                    }
                },
                error: function() {
                    alert('An error occurred while unblocking the IP address.');
                    button.prop('disabled', false).text('Unblock');
                }
            });
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
                $('#ms-logs-tbody').html('<tr><td colspan="7">Loading...</td></tr>');
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
                            html += '<td>' + escapeHtml(log.description) + '</td>';
                            html += '<td><span class="severity-' + escapeHtml(log.severity) + '">' + escapeHtml(log.severity) + '</span></td>';
                            html += '</tr>';
                        });
                    } else {
                        html = '<tr><td colspan="7">No logs found</td></tr>';
                    }

                    $('#ms-logs-tbody').html(html);

                    // Update pagination
                    updatePagination(total, limit, offset);
                }
            },
            error: function() {
                $('#ms-logs-tbody').html('<tr><td colspan="7">Error loading logs</td></tr>');
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

            // Previous page
            if (currentPage > 1) {
                html += '<a class="prev-page button" data-offset="' + ((currentPage - 2) * limit) + '">‹</a>';
            }

            // Page numbers
            for (var i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
                if (i === currentPage) {
                    html += '<span class="paging-input"><span class="tablenav-paging-text">' + i + ' of ' + totalPages + '</span></span>';
                } else {
                    html += '<a class="page-numbers button" data-offset="' + ((i - 1) * limit) + '">' + i + '</a>';
                }
            }

            // Next page
            if (currentPage < totalPages) {
                html += '<a class="next-page button" data-offset="' + (currentPage * limit) + '">›</a>';
            }

            html += '</span>';
            html += '</div>';
        }

        $('#ms-logs-pagination').html(html);

        // Bind pagination events
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

    // Refresh stats every 30 seconds
    setInterval(loadSecurityStats, 30000);

    // Auto-refresh logs every 60 seconds if on logs page
    if ($('#ms-logs-table').length > 0) {
        setInterval(function() {
            loadSecurityLogs();
        }, 60000);
    }
});
