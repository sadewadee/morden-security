jQuery(document).ready(function($) {
    'use strict';

    const $startFullScanButton = $('#ms-start-full-scan');
    const $startQuickScanButton = $('#ms-start-quick-scan');
    const $resultsContainer = $('.ms-scan-results');
    const $navTabs = $('.nav-tab-wrapper .nav-tab');
    const $tabContents = $('.tab-content');

    let scanning = false;
    let scanInterval;

    // --- Tab Handling ---
    $navTabs.on('click', function(e) {
        e.preventDefault();
        const target = $(this).attr('href');

        $navTabs.removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');

        $tabContents.removeClass('active');
        $(target).addClass('active');
    });


    // --- Scan Logic ---
    function startScan(scanType) {
        if (scanning) return;
        scanning = true;

        $startFullScanButton.prop('disabled', true);
        $startQuickScanButton.prop('disabled', true);
        $resultsContainer.html('<p>Initializing scan...</p>');

        $.post(msAdmin.ajax_url, {
            action: 'ms_start_integrity_scan',
            nonce: msAdmin.nonce,
            scan_type: scanType
        }).done(function(response) {
            if (response.success) {
                scanInterval = setInterval(getScanStatus, 3000); // Poll every 3 seconds
            } else {
                $resultsContainer.html('<p class="ms-error">' + (response.data.message || 'Failed to start scan.') + '</p>');
                resetScannerUI();
            }
        }).fail(function() {
            $resultsContainer.html('<p class="ms-error">An AJAX error occurred.</p>');
            resetScannerUI();
        });
    }

    function getScanStatus() {
        $.get(msAdmin.ajax_url, {
            action: 'ms_get_scan_status',
            nonce: msAdmin.nonce
        }).done(function(response) {
            if (response.success) {
                const data = response.data;
                updateSummary(data);

                if (data.progress >= 100) {
                    clearInterval(scanInterval);
                    getScanResults();
                    resetScannerUI();
                }
            } else {
                clearInterval(scanInterval);
                $resultsContainer.html('<p class="ms-error">' + (response.data.message || 'Failed to get status.') + '</p>');
                resetScannerUI();
            }
        }).fail(function() {
            clearInterval(scanInterval);
            $resultsContainer.html('<p class="ms-error">An AJAX error occurred while checking status.</p>');
            resetScannerUI();
        });
    }

    function getScanResults() {
        $resultsContainer.html('<p>Loading final results...</p>');
        $.get(msAdmin.ajax_url, {
            action: 'ms_get_scan_results',
            nonce: msAdmin.nonce
        }).done(function(response) {
            if (response.success) {
                renderResults(response.data);
            } else {
                $resultsContainer.html('<p class="ms-error">' + (response.data.message || 'Failed to load results.') + '</p>');
            }
        }).fail(function() {
            $resultsContainer.html('<p class="ms-error">An AJAX error occurred while loading results.</p>');
        });
    }

    function updateSummary(data) {
        $('#ms-scan-progress-text').text(data.files_scanned + ' / ' + data.total_files);
        $('#ms-scan-issues-text').text(data.issues_found + ' / ' + data.issues_found); // Assuming critical = total for now
        // Update other summary fields if data is available
    }

    function renderResults(results) {
        let html = '';
        if (!results || results.length === 0) {
            html = '<p class="ms-success">No issues found.</p>';
        } else {
            html += '<table class="wp-list-table widefat fixed striped">';
            html += '<thead><tr><th>File Path</th><th>Issue</th><th>Actions</th></tr></thead>';
            html += '<tbody>';
            results.forEach(function(item) {
                html += `<tr>
                    <td><code>${item.file_path}</code></td>
                    <td>${item.issue_type.replace(/_/g, ' ')}</td>
                    <td>
                        <button class="button button-small">View Diff</button>
                        <button class="button button-small">Restore</button>
                    </td>
                </tr>`;
            });
            html += '</tbody></table>';
        }
        $resultsContainer.html(html);
    }

    function resetScannerUI() {
        scanning = false;
        $startFullScanButton.prop('disabled', false);
        $startQuickScanButton.prop('disabled', false);
    }

    // --- Event Handlers ---
    $startFullScanButton.on('click', function() {
        startScan('full');
    });
    $startQuickScanButton.on('click', function() {
        startScan('quick');
    });

    // --- Initial Load ---
    getScanResults();
});
