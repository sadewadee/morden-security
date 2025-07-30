(function($) {
    'use strict';

    const MordenIPManagement = {
        init() {
            this.bindEvents();
            this.initializeDataTables();
            this.setupIPValidation();
        },

        bindEvents() {
            $(document).on('click', '.ms-block-ip', this.handleBlockIP);
            $(document).on('click', '.ms-unblock-ip', this.handleUnblockIP);
            $(document).on('click', '.ms-view-logs', this.handleViewLogs);
            $(document).on('click', '.ms-remove-whitelist', this.handleRemoveWhitelist);
            $(document).on('click', '#bulk-unblock', this.handleBulkUnblock);
            $(document).on('change', '#cb-select-all', this.handleSelectAll);
            $(document).on('click', '#filter-ips', this.handleFilterIPs);
            $(document).on('submit', '.ms-ip-rule-form', this.handleAddIPRule);
        },

        handleBlockIP(e) {
            e.preventDefault();

            const $button = $(this);
            const ipAddress = $button.data('ip');
            const reason = prompt('Enter reason for blocking this IP:', 'Manual block');

            if (!reason) return;

            $button.prop('disabled', true).text('Blocking...');

            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                 {
                    action: 'ms_block_ip',
                    nonce: msAdmin.nonce,
                    ip_address: ipAddress,
                    reason: reason,
                    duration: 'permanent'
                },
                success(response) {
                    if (response.success) {
                        $button.removeClass('ms-block-ip button-primary')
                              .addClass('ms-unblock-ip')
                              .text('Unblock')
                              .prop('disabled', false);
                        MordenIPManagement.showNotice('success', response.data);
                        MordenIPManagement.refreshIPTable();
                    } else {
                        MordenIPManagement.showNotice('error', response.data);
                        $button.prop('disabled', false).text('Block');
                    }
                },
                error() {
                    MordenIPManagement.showNotice('error', 'An error occurred while blocking the IP.');
                    $button.prop('disabled', false).text('Block');
                }
            });
        },

        handleUnblockIP(e) {
            e.preventDefault();

            const $button = $(this);
            const ipAddress = $button.data('ip');

            if (!confirm(`Are you sure you want to unblock ${ipAddress}?`)) {
                return;
            }

            $button.prop('disabled', true).text('Unblocking...');

            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                 {
                    action: 'ms_unblock_ip',
                    nonce: msAdmin.nonce,
                    ip_address: ipAddress
                },
                success(response) {
                    if (response.success) {
                        $button.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                        });
                        MordenIPManagement.showNotice('success', response.data);
                    } else {
                        MordenIPManagement.showNotice('error', response.data);
                        $button.prop('disabled', false).text('Unblock');
                    }
                },
                error() {
                    MordenIPManagement.showNotice('error', 'An error occurred while unblocking the IP.');
                    $button.prop('disabled', false).text('Unblock');
                }
            });
        },

        handleViewLogs(e) {
            e.preventDefault();

            const ipAddress = $(this).data('ip');
            const modal = this.createIPLogsModal(ipAddress);

            modal.find('.modal-body').html('<div class="loading">Loading IP logs...</div>');
            modal.show();

            this.loadIPLogs(ipAddress, modal);
        },

        handleRemoveWhitelist(e) {
            e.preventDefault();

            const $button = $(this);
            const botId = $button.data('bot-id');

            if (!confirm('Are you sure you want to remove this bot from whitelist?')) {
                return;
            }

            $button.prop('disabled', true).text('Removing...');

            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                 {
                    action: 'ms_remove_bot_whitelist',
                    nonce: msAdmin.nonce,
                    bot_id: botId
                },
                success(response) {
                    if (response.success) {
                        $button.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                        });
                        MordenIPManagement.showNotice('success', 'Bot removed from whitelist');
                    } else {
                        MordenIPManagement.showNotice('error', response.data);
                        $button.prop('disabled', false).text('Remove');
                    }
                },
                error() {
                    MordenIPManagement.showNotice('error', 'An error occurred while removing the bot.');
                    $button.prop('disabled', false).text('Remove');
                }
            });
        },

        handleBulkUnblock(e) {
            e.preventDefault();

            const selectedIPs = $('input[name="blocked_ips[]"]:checked').map(function() {
                return $(this).val();
            }).get();

            if (selectedIPs.length === 0) {
                alert('Please select IPs to unblock');
                return;
            }

            if (!confirm(`Unblock ${selectedIPs.length} IP addresses?`)) {
                return;
            }

            this.bulkUnblockIPs(selectedIPs);
        },

        handleSelectAll(e) {
            const checked = $(this).prop('checked');
            $('input[name="blocked_ips[]"]').prop('checked', checked);
        },

        handleFilterIPs(e) {
            e.preventDefault();

            const ruleType = $('#filter-rule-type').val();
            const countryCode = $('#filter-country').val();
            const threatLevel = $('#filter-threat-level').val();

            this.filterIPTable({
                rule_type: ruleType,
                country_code: countryCode,
                threat_level: threatLevel
            });
        },

        handleAddIPRule(e) {
            e.preventDefault();

            const $form = $(this);
            const formData = $form.serialize();

            const ipAddress = $form.find('input[name="ip_address"]').val();
            if (!this.validateIPAddress(ipAddress)) {
                this.showNotice('error', 'Please enter a valid IP address');
                return;
            }

            $form.find('input[type="submit"]').prop('disabled', true).val('Adding Rule...');

            $.ajax({
                url: '',
                type: 'POST',
                 formData,
                success(response) {
                    if (response && response.includes('success')) {
                        MordenIPManagement.showNotice('success', 'IP rule added successfully');
                        $form[0].reset();
                        MordenIPManagement.refreshIPTable();
                    } else {
                        MordenIPManagement.showNotice('error', 'Failed to add IP rule');
                    }
                    $form.find('input[type="submit"]').prop('disabled', false).val('Add IP Rule');
                },
                error() {
                    MordenIPManagement.showNotice('error', 'An error occurred while adding the IP rule');
                    $form.find('input[type="submit"]').prop('disabled', false).val('Add IP Rule');
                }
            });
        },

        initializeDataTables() {
            if ($.fn.DataTable) {
                $('.ms-ip-table').DataTable({
                    pageLength: 25,
                    order: [[0, 'desc']],
                    columnDefs: [
                        { orderable: false, targets: [0, -1] }
                    ],
                    language: {
                        search: 'Search IPs:',
                        lengthMenu: 'Show _MENU_ entries per page',
                        info: 'Showing _START_ to _END_ of _TOTAL_ IP rules'
                    }
                });
            }
        },

        setupIPValidation() {
            $('input[name="ip_address"]').on('blur', function() {
                const ip = $(this).val();
                const $feedback = $(this).siblings('.ip-validation-feedback');

                if (ip && !MordenIPManagement.validateIPAddress(ip)) {
                    if ($feedback.length === 0) {
                        $(this).after('<div class="ip-validation-feedback error">Invalid IP address format</div>');
                    }
                    $(this).addClass('error');
                } else {
                    $feedback.remove();
                    $(this).removeClass('error');
                }
            });
        },

        validateIPAddress(ip) {
            const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
            const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;

            return ipv4Regex.test(ip) || ipv6Regex.test(ip) || cidrRegex.test(ip);
        },

        loadIPLogs(ipAddress, modal) {
            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                 {
                    action: 'ms_get_ip_logs',
                    nonce: msAdmin.nonce,
                    ip_address: ipAddress
                },
                success(response) {
                    if (response.success) {
                        const logs = response.data;
                        let html = '<div class="ip-logs-container">';

                        if (logs.length === 0) {
                            html += '<p>No logs found for this IP address.</p>';
                        } else {
                            html += '<table class="widefat"><thead><tr>';
                            html += '<th>Time</th><th>Event</th><th>Severity</th><th>Message</th>';
                            html += '</tr></thead><tbody>';

                            logs.forEach(log => {
                                html += `<tr>
                                    <td>${new Date(log.timestamp * 1000).toLocaleString()}</td>
                                    <td><span class="ms-event-type ms-event-${log.event_type}">${log.event_type}</span></td>
                                    <td><span class="ms-severity ms-severity-${log.severity}">${log.severity}</span></td>
                                    <td>${log.message}</td>
                                </tr>`;
                            });

                            html += '</tbody></table>';
                        }

                        html += '</div>';
                        modal.find('.modal-body').html(html);
                    } else {
                        modal.find('.modal-body').html('<p>Failed to load IP logs.</p>');
                    }
                },
                error() {
                    modal.find('.modal-body').html('<p>Error loading IP logs.</p>');
                }
            });
        },

        filterIPTable(filters) {
            const $table = $('.ms-ip-table tbody');
            const $rows = $table.find('tr');

            $rows.each(function() {
                const $row = $(this);
                let show = true;

                if (filters.rule_type && filters.rule_type !== '') {
                    const ruleType = $row.find('.ms-block-type').text().toLowerCase();
                    if (ruleType.indexOf(filters.rule_type) === -1) {
                        show = false;
                    }
                }

                if (filters.country_code && filters.country_code !== '') {
                    const countryCode = $row.find('td:nth-child(3)').text().trim();
                    if (countryCode !== filters.country_code) {
                        show = false;
                    }
                }

                if (filters.threat_level && filters.threat_level !== '') {
                    const threatScore = parseInt($row.find('.ms-threat-score').text());
                    const minScore = parseInt(filters.threat_level);
                    if (threatScore < minScore) {
                        show = false;
                    }
                }

                $row.toggle(show);
            });
        },

        refreshIPTable() {
            setTimeout(() => {
                location.reload();
            }, 1000);
        },

        bulkUnblockIPs(ipAddresses) {
            const promises = ipAddresses.map(ip => {
                return $.ajax({
                    url: msAdmin.ajaxUrl,
                    type: 'POST',
                     {
                        action: 'ms_unblock_ip',
                        nonce: msAdmin.nonce,
                        ip_address: ip
                    }
                });
            });

            Promise.all(promises).then(results => {
                const successful = results.filter(r => r.success).length;
                this.showNotice('success', `Successfully unblocked ${successful} IP addresses`);

                $('input[name="blocked_ips[]"]:checked').closest('tr').fadeOut(300, function() {
                    $(this).remove();
                });
            }).catch(() => {
                this.showNotice('error', 'Some IPs could not be unblocked');
            });
        },

        createIPLogsModal(ipAddress) {
            const modalHtml = `
                <div class="ms-ip-logs-modal">
                    <div class="modal-overlay"></div>
                    <div class="modal-content">
                        <div class="modal-header">
                            <h3>Security Logs for ${ipAddress}</h3>
                            <button type="button" class="modal-close">&times;</button>
                        </div>
                        <div class="modal-body"></div>
                    </div>
                </div>
            `;

            const $modal = $(modalHtml).appendTo('body');

            $modal.find('.modal-close, .modal-overlay').on('click', function() {
                $modal.fadeOut(300, function() {
                    $(this).remove();
                });
            });

            return $modal;
        },

        showNotice(type, message) {
            const $notice = $(`<div class="notice notice-${type} is-dismissible"><p>${message}</p></div>`);
            $('.wrap h1').after($notice);

            setTimeout(() => {
                $notice.fadeOut(300, function() {
                    $(this).remove();
                });
            }, 5000);
        }
    };

    $(document).ready(() => {
        MordenIPManagement.init();
    });

})(jQuery);
