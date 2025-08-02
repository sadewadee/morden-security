(function($) {
    'use strict';

    const BotDetectionManager = {
        init() {
            if ($('#botTrendsChart').length || $('#botTypesChart').length) {
                this.loadChartData();
            }
        },

        loadChartData() {
            $.ajax({
                url: msAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'ms_get_bot_detection_stats',
                    nonce: msAdmin.nonce
                },
                success(response) {
                    if (response.success) {
                        if ($('#botTrendsChart').length) {
                            BotDetectionManager.renderBotTrendsChart(response.data.trends);
                        }
                        if ($('#botTypesChart').length) {
                            BotDetectionManager.renderBotTypesChart(response.data.types);
                        }
                    }
                }
            });
        },

        renderBotTrendsChart(trends) {
            const ctx = document.getElementById('botTrendsChart').getContext('2d');
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: Object.keys(trends),
                    datasets: [{
                        label: 'Bot Detections',
                        data: Object.values(trends),
                        borderColor: '#fd7e14',
                        backgroundColor: 'rgba(253, 126, 20, 0.1)',
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        },

        renderBotTypesChart(types) {
            const ctx = document.getElementById('botTypesChart').getContext('2d');
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(types),
                    datasets: [{
                        data: Object.values(types),
                        backgroundColor: ['#dc3545', '#28a745', '#ffc107', '#6c757d']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }
    };

    $(document).ready(() => {
        BotDetectionManager.init();
    });

})(jQuery);