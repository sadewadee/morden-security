(function() {
    'use strict';

    const MordenBotTracking = {
        init() {
            this.trackBehavior();
            this.monitorSuspiciousActivity();
        },

        trackBehavior() {
            const behaviorData = {
                mouseMovements: 0,
                keystrokes: 0,
                scrollEvents: 0,
                clickEvents: 0,
                sessionStart: Date.now()
            };

            document.addEventListener('mousemove', () => {
                behaviorData.mouseMovements++;
            });

            document.addEventListener('keydown', () => {
                behaviorData.keystrokes++;
            });

            document.addEventListener('scroll', () => {
                behaviorData.scrollEvents++;
            });

            document.addEventListener('click', () => {
                behaviorData.clickEvents++;
            });

            setTimeout(() => {
                this.submitBehaviorData(behaviorData);
            }, 30000);
        },

        monitorSuspiciousActivity() {
            let rapidRequests = 0;
            const startTime = Date.now();

            const observer = new PerformanceObserver((list) => {
                const entries = list.getEntries();
                entries.forEach(entry => {
                    if (entry.entryType === 'navigation' || entry.entryType === 'fetch') {
                        rapidRequests++;

                        if (rapidRequests > 10 && (Date.now() - startTime) < 10000) {
                            this.flagSuspiciousActivity('rapid_requests');
                        }
                    }
                });
            });

            observer.observe({ entryTypes: ['navigation', 'fetch'] });
        },

        submitBehaviorData(data) {
            if (typeof msAjax === 'undefined') return;

            const totalInteractions = data.mouseMovements + data.keystrokes +
                                    data.scrollEvents + data.clickEvents;

            if (totalInteractions < 3) {
                this.flagSuspiciousActivity('low_interaction');
            }

            fetch(msAjax.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    action: 'ms_track_behavior',
                    nonce: msAjax.nonce,
                    behavior_ JSON.stringify(data)
                })
            }).catch(() => {});
        },

        flagSuspiciousActivity(reason) {
            if (typeof msAjax === 'undefined') return;

            fetch(msAjax.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    action: 'ms_flag_suspicious',
                    nonce: msAjax.nonce,
                    reason: reason,
                    timestamp: Date.now()
                })
            }).catch(() => {});
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            MordenBotTracking.init();
        });
    } else {
        MordenBotTracking.init();
    }

})();
