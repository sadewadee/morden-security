(function($) {
    'use strict';

    const MordenSecurityAdmin = {
        init() {
            this.bindEvents();
            this.initializeRealTimeUpdates();
            this.loadSecurityStats();
            this.handleTabSwitching();
        },

        bindEvents() {
            $(document).on('click', '.ms-block-ip', e => this.handleBlockIP(e));
            $(document).on('click', '.ms-unblock-ip', e => this.handleUnblockIP(e));
            $(document).on('click', '.ms-view-details', e => this.handleViewDetails(e));
            $(document).on('click', '.ms-view-logs', e => this.handleViewLogs(e));
            $(document).on('click', '#bulk-unblock', e => this.handleBulkUnblock(e));
            $(document).on('change', '#cb-select-all', e => this.handleSelectAll(e));
        },

        handleTabSwitching() {
            $('.nav-tab-wrapper a').on('click', function(e) {
                e.preventDefault();
                const target = $(this).attr('href');
                $('.nav-tab').removeClass('nav-tab-active');
                $(this).addClass('nav-tab-active');
                $('.tab-content').removeClass('active');
                $(target).addClass('active');
            });
        },

        handleBlockIP(e) {
            e.preventDefault();
            const $button = $(e.currentTarget);
            const ipAddress = $button.data('ip');
            if (!confirm(msAdmin.strings.confirmBlock)) {
                return;
            }
            $button.prop('disabled', true).text('Blocking...');
            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'ms_block_ip',
                    nonce: msAdmin.nonce,
                    ip_address: ipAddress,
                    reason: 'manual_block',
                    duration: 'permanent'
                },
                success: (response) => {
                    if (response.success) {
                        $button.removeClass('ms-block-ip button-primary')
                              .addClass('ms-unblock-ip')
                              .text('Unblock')
                              .prop('disabled', false);
                        this.showNotice('success', response.data);
                    } else {
                        this.showNotice('error', response.data);
                        $button.prop('disabled', false).text('Block');
                    }
                },
                error: () => {
                    this.showNotice('error', msAdmin.strings.error);
                    $button.prop('disabled', false).text('Block');
                }
            });
        },

        handleUnblockIP(e) {
            e.preventDefault();
            const $button = $(e.currentTarget);
            const ipAddress = $button.data('ip');
            if (!confirm(msAdmin.strings.confirmUnblock)) {
                return;
            }
            $button.prop('disabled', true).text('Unblocking...');
            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'ms_unblock_ip',
                    nonce: msAdmin.nonce,
                    ip_address: ipAddress
                },
                success: (response) => {
                    if (response.success) {
                        $button.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                        });
                        this.showNotice('success', response.data);
                    } else {
                        this.showNotice('error', response.data);
                        $button.prop('disabled', false).text('Unblock');
                    }
                },
                error: () => {
                    this.showNotice('error', msAdmin.strings.error);
                    $button.prop('disabled', false).text('Unblock');
                }
            });
        },

        handleViewDetails(e) {
            e.preventDefault();
            const ipAddress = $(e.currentTarget).data('ip');
            const modal = this.createModal('IP Details: ' + ipAddress);
            modal.find('.modal-body').html('<div class="loading">Loading details...</div>');
            modal.modal('show');
            this.loadIPDetails(ipAddress, modal);
        },

        handleViewLogs(e) {
            e.preventDefault();
            const ipAddress = $(e.currentTarget).data('ip');
            const modal = this.createModal('Event Logs for: ' + ipAddress);
            modal.find('.modal-body').html('<div class="loading">Loading logs...</div>');
            modal.modal('show');
            this.loadIPLogs(ipAddress, modal);
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
            const checked = $(e.currentTarget).prop('checked');
            $('input[name="blocked_ips[]"]').prop('checked', checked);
        },

        loadSecurityStats() {
            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'ms_get_security_stats',
                    nonce: msAdmin.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateStatsDisplay(response.data);
                    }
                }
            });
        },

        updateStatsDisplay(stats) {
            $('.ms-stat-card.blocked .ms-stat-number').text(this.formatNumber(stats.blocked_requests));
            $('.ms-stat-card.bots .ms-stat-number').text(this.formatNumber(stats.bot_detections));
            $('.ms-stat-card.firewall .ms-stat-number').text(this.formatNumber(stats.firewall_blocks));
            $('.ms-stat-card.total .ms-stat-number').text(this.formatNumber(stats.total_events));
            this.updateThreatLevel(stats.threat_level);
        },

        updateThreatLevel(level) {
            const $card = $('.ms-threat-level-card');
            $card.removeClass('ms-threat-low ms-threat-medium ms-threat-high ms-threat-critical');
            $card.addClass(`ms-threat-${level}`);
            $('.ms-threat-level').text(level.charAt(0).toUpperCase() + level.slice(1));
        },

        initializeRealTimeUpdates() {
            if (typeof EventSource === 'undefined') {
                return;
            }
            setInterval(() => {
                this.loadSecurityStats();
            }, 30000);
        },

        initializeCharts() {
            if ($('#botTrendsChart').length) {
                this.renderBotTrendsChart();
            }
            if ($('#botTypesChart').length) {
                this.renderBotTypesChart();
            }
        },

        renderBotTrendsChart() {},

        loadIPDetails(ipAddress, modal) {
            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'ms_get_ip_details',
                    nonce: msAdmin.nonce,
                    ip_address: ipAddress
                },
                success: (response) => {
                    if (response.success) {
                        const details = response.data;
                        let html = `
                            <div class="ip-details">
                                <h4>Security Events</h4>
                                <table class="widefat">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>Event</th>
                                            <th>Severity</th>
                                            <th>Message</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                        `;
                        details.events.forEach(event => {
                            html += `
                                <tr>
                                    <td>${new Date(event.timestamp * 1000).toLocaleString()}</td>
                                    <td><span class="ms-event-type ms-event-${event.event_type}">${event.event_type}</span></td>
                                    <td><span class="ms-severity ms-severity-${event.severity}">${event.severity}</span></td>
                                    <td>${event.message}</td>
                                </tr>
                            `;
                        });
                        html += `
                                    </tbody>
                                </table>
                                <div class="ip-stats">
                                    <h4>Statistics</h4>
                                    <p><strong>Total Events:</strong> ${details.total_events}</p>
                                    <p><strong>Threat Score:</strong> ${details.threat_score}</p>
                                    <p><strong>Country:</strong> ${details.country}</p>
                                </div>
                            </div>
                        `;
                        modal.find('.modal-body').html(html);
                    } else {
                        modal.find('.modal-body').html('<p>Failed to load IP details.</p>');
                    }
                },
                error: () => {
                    modal.find('.modal-body').html('<p>Error loading IP details.</p>');
                }
            });
        },

        loadIPLogs(ipAddress, modal) {
            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'ms_get_ip_logs',
                    nonce: msAdmin.nonce,
                    ip_address: ipAddress
                },
                success: (response) => {
                    if (response.success) {
                        const logs = response.data;
                        let html = '<table class="widefat"><thead><tr><th>Time</th><th>Event</th><th>Message</th></tr></thead><tbody>';
                        logs.forEach(log => {
                            html += `<tr>
                                <td>${new Date(log.timestamp * 1000).toLocaleString()}</td>
                                <td><span class="ms-event-type ms-event-${log.event_type}">${log.event_type}</span></td>
                                <td>${log.message}</td>
                            </tr>`;
                        });
                        html += '</tbody></table>';
                        modal.find('.modal-body').html(html);
                    } else {
                        modal.find('.modal-body').html('<p>Failed to load logs.</p>');
                    }
                },
                error: () => {
                    modal.find('.modal-body').html('<p>Error loading logs.</p>');
                }
            });
        },

        bulkUnblockIPs(ipAddresses) {
            const promises = ipAddresses.map(ip => {
                return $.ajax({
                    url: msAdmin.ajaxUrl,
                    type: 'POST',
                    data: {
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

        createModal(title) {
            const modalHtml = `
                <div class="modal fade" tabindex="-1">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">${title}</h5>
                                <button type="button" class="close" data-dismiss="modal">
                                    <span>&times;</span>
                                </button>
                            </div>
                            <div class="modal-body"></div>
                        </div>
                    </div>
                </div>
            `;
            return $(modalHtml).appendTo('body');
        },

        showNotice(type, message) {
            const $notice = $(`<div class="notice notice-${type} is-dismissible"><p>${message}</p></div>`);
            $('.wrap h1').after($notice);
            setTimeout(() => {
                $notice.fadeOut(300, function() {
                    $(this).remove();
                });
            }, 5000);
        },

        formatNumber(number) {
            return new Intl.NumberFormat().format(number);
        }
    };

    $(document).ready(() => {
        MordenSecurityAdmin.init();
    });

    const ResponsiveUtils = {
        init() {
            this.handleViewportChanges();
            this.optimizeTablesForMobile();
            this.handleModalResize();
        },

        handleViewportChanges() {
            let resizeTimer;
            $(window).on('resize', () => {
                clearTimeout(resizeTimer);
                resizeTimer = setTimeout(() => {
                    this.optimizeTablesForMobile();
                    this.adjustCardLayout();
                }, 250);
            });
        },

        optimizeTablesForMobile() {
            const $tables = $('.ms-table-container table');
            const isMobile = window.innerWidth < 768;
            if (isMobile) {
                $tables.each(function() {
                    $(this).addClass('ms-mobile-table');
                });
            } else {
                $tables.removeClass('ms-mobile-table');
            }
        },

        adjustCardLayout() {
            const $statCards = $('.ms-stat-cards');
            const containerWidth = $statCards.width();
            const cardMinWidth = 180;
            const gap = 15;
            const columns = Math.floor((containerWidth + gap) / (cardMinWidth + gap));
            $statCards.css('grid-template-columns', `repeat(${Math.max(1, columns)}, 1fr)`);
        },

        handleModalResize() {
            $(window).on('resize', () => {
                $('.ms-modal-content').each(function() {
                    const $modal = $(this);
                    const maxHeight = $(window).height() * 0.9;
                    $modal.css('max-height', maxHeight + 'px');
                    const $body = $modal.find('.ms-modal-body');
                    const headerHeight = $modal.find('.ms-modal-header').outerHeight() || 60;
                    $body.css('max-height', (maxHeight - headerHeight - 40) + 'px');
                });
            });
        }
    };

    $(document).ready(() => {
        ResponsiveUtils.init();
    });
})(jQuery);
