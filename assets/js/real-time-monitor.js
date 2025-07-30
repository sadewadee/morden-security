(function($) {
    'use strict';

    const MordenRealTimeMonitor = {
        wsConnection: null,
        reconnectAttempts: 0,
        maxReconnectAttempts: 5,

        init() {
            this.initializeWebSocket();
            this.bindEvents();
            this.startPolling();
        },

        initializeWebSocket() {
            if (typeof WebSocket === 'undefined') {
                console.log('WebSocket not supported, falling back to polling');
                return;
            }

            const wsUrl = `wss://${window.location.host}/ws/morden-security`;

            try {
                this.wsConnection = new WebSocket(wsUrl);

                this.wsConnection.onopen = () => {
                    console.log('Real-time monitoring connected');
                    this.reconnectAttempts = 0;
                };

                this.wsConnection.onmessage = (event) => {
                    this.handleRealTimeUpdate(JSON.parse(event.data));
                };

                this.wsConnection.onclose = () => {
                    this.handleDisconnection();
                };

                this.wsConnection.onerror = (error) => {
                    console.error('WebSocket error:', error);
                };

            } catch (error) {
                console.error('Failed to initialize WebSocket:', error);
            }
        },

        handleRealTimeUpdate(data) {
            switch (data.type) {
                case 'security_event':
                    this.updateSecurityEvent(data.payload);
                    break;
                case 'threat_level_change':
                    this.updateThreatLevel(data.payload);
                    break;
                case 'ip_blocked':
                    this.showBlockNotification(data.payload);
                    break;
                case 'stats_update':
                    this.updateDashboardStats(data.payload);
                    break;
            }
        },

        updateSecurityEvent(event) {
            const $eventsTable = $('.ms-recent-events tbody');
            const $newRow = this.createEventRow(event);

            $eventsTable.prepend($newRow);
            $newRow.addClass('ms-new-event').fadeIn(300);

            setTimeout(() => {
                $newRow.removeClass('ms-new-event');
            }, 3000);

            if ($eventsTable.find('tr').length > 50) {
                $eventsTable.find('tr:last').remove();
            }
        },

        updateThreatLevel(threatData) {
            const $threatCard = $('.ms-threat-level-card');
            const currentLevel = $threatCard.attr('class').match(/ms-threat-(\w+)/)?.[1];

            if (currentLevel !== threatData.level) {
                $threatCard.removeClass(`ms-threat-${currentLevel}`)
                          .addClass(`ms-threat-${threatData.level}`);

                $('.ms-threat-level').text(threatData.level.charAt(0).toUpperCase() +
                                         threatData.level.slice(1));

                this.showThreatLevelAlert(threatData.level, currentLevel);
            }
        },

        showBlockNotification(blockData) {
            const notification = `
                <div class="ms-real-time-notification ms-block-notification">
                    <div class="ms-notification-content">
                        <strong>IP Blocked:</strong> ${blockData.ip_address}
                        <br><small>Reason: ${blockData.reason}</small>
                    </div>
                    <button class="ms-notification-close">&times;</button>
                </div>
            `;

            $('body').append(notification);

            setTimeout(() => {
                $('.ms-block-notification').fadeOut(300, function() {
                    $(this).remove();
                });
            }, 5000);
        },

        updateDashboardStats(stats) {
            Object.keys(stats).forEach(statKey => {
                const $statElement = $(`.ms-stat-card.${statKey} .ms-stat-number`);
                if ($statElement.length) {
                    this.animateCounter($statElement, parseInt($statElement.text().replace(/,/g, '')),
                                     stats[statKey]);
                }
            });
        },

        animateCounter($element, from, to) {
            const duration = 1000;
            const start = Date.now();

            const animate = () => {
                const elapsed = Date.now() - start;
                const progress = Math.min(elapsed / duration, 1);
                const current = Math.round(from + (to - from) * progress);

                $element.text(this.formatNumber(current));

                if (progress < 1) {
                    requestAnimationFrame(animate);
                }
            };

            animate();
        },

        createEventRow(event) {
            return $(`
                <tr class="ms-new-event">
                    <td>${new Date(event.timestamp * 1000).toLocaleTimeString()}</td>
                    <td>
                        <span class="ms-event-type ms-event-${event.event_type}">
                            ${event.event_type.replace(/_/g, ' ')}
                        </span>
                    </td>
                    <td><code>${event.ip_address}</code></td>
                    <td>
                        <span class="ms-severity ms-severity-${event.severity}">
                            ${this.getSeverityLabel(event.severity)}
                        </span>
                    </td>
                    <td>${event.message}</td>
                    <td>
                        <button class="button button-small ms-block-ip" data-ip="${event.ip_address}">
                            Block IP
                        </button>
                    </td>
                </tr>
            `);
        },

        showThreatLevelAlert(newLevel, oldLevel) {
            if (newLevel === 'critical' || (newLevel === 'high' && oldLevel !== 'critical')) {
                const alert = `
                    <div class="ms-threat-alert ms-alert-${newLevel}">
                        <h3>Threat Level Changed</h3>
                        <p>Threat level escalated from <strong>${oldLevel}</strong> to <strong>${newLevel}</strong></p>
                        <button class="button" onclick="$(this).closest('.ms-threat-alert').remove()">
                            Acknowledge
                        </button>
                    </div>
                `;

                $('body').append(alert);
            }
        },

        handleDisconnection() {
            if (this.reconnectAttempts < this.maxReconnectAttempts) {
                this.reconnectAttempts++;
                console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

                setTimeout(() => {
                    this.initializeWebSocket();
                }, 5000 * this.reconnectAttempts);
            } else {
                console.log('Max reconnection attempts reached, falling back to polling');
                this.startPolling();
            }
        },

        startPolling() {
            setInterval(() => {
                this.fetchLatestData();
            }, 30000);
        },

        fetchLatestData() {
            if (typeof msAdmin === 'undefined') return;

            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'ms_get_security_stats',
                    nonce: msAdmin.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateDashboardStats(response.data);
                    }
                }
            });
        },

        bindEvents() {
            $(document).on('click', '.ms-notification-close', function() {
                $(this).closest('.ms-real-time-notification').fadeOut(300, function() {
                    $(this).remove();
                });
            });
        },

        getSeverityLabel(severity) {
            const labels = {1: 'Info', 2: 'Low', 3: 'Medium', 4: 'High'};
            return labels[severity] || 'Unknown';
        },

        formatNumber(number) {
            return new Intl.NumberFormat().format(number);
        }
    };

    $(document).ready(() => {
        if ($('.ms-dashboard-grid').length) {
            MordenRealTimeMonitor.init();
        }
    });

})(jQuery);
