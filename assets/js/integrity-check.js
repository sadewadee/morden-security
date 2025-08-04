jQuery(document).ready(function($) {
    'use strict';

    // --- DOM Elements ---
    const $scanContainer = $('.ms-scanner-main');
    const $startFullScanButton = $('#ms-start-full-scan');
    const $startQuickScanButton = $('#ms-start-quick-scan');
    const $resultsSummaryContainer = $('.ms-scan-results-summary');
    const $navTabs = $('.nav-tab-wrapper .nav-tab');
    const $tabContents = $('.tab-content');
    const $progressBar = $('#ms-progress-bar');
    const $progressBarInner = $('#ms-progress-bar-inner');
    const $progressPercentage = $('#ms-progress-percentage');
    const $scanProgressText = $('#ms-scan-progress-text');
    const $scanIssuesText = $('#ms-scan-issues-text');

    // --- State ---
    let scanStatusInterval;
    let isScanning = false;

    // --- Functions ---

    /**
     * Handles tab navigation.
     */
    function setupTabNavigation() {
        $navTabs.on('click', function(e) {
            e.preventDefault();
            const target = $(this).attr('href');
            $navTabs.removeClass('nav-tab-active');
            $(this).addClass('nav-tab-active');
            $tabContents.removeClass('active');
            $(target).addClass('active');
        });
    }

    /**
     * Initiates a new scan.
     * @param {string} scanType - The type of scan ('full' or 'quick').
     */
    function startScan(scanType) {
        if (isScanning) return;
        isScanning = true;

        // Update UI to show scanning has started
        $startFullScanButton.prop('disabled', true).text('Scanning...');
        $startQuickScanButton.prop('disabled', true);
        $resultsSummaryContainer.html('<p>Initializing scan...</p>').show();
        $progressBar.show();
        updateProgressUI(0, 0, 0, 0); // Reset progress bar

        // Make AJAX call to start the scan in the background
        $.post(msAdmin.ajax_url, {
            action: 'ms_start_integrity_scan',
            nonce: msAdmin.nonce,
            scan_type: scanType
        }).done(function(response) {
            if (response.success) {
                // Start polling for status updates
                scanStatusInterval = setInterval(updateScanStatus, 2000);
            } else {
                $resultsSummaryContainer.html(`<p class="ms-error">${response.data.message || 'Failed to start scan.'}</p>`);
                resetScannerUI();
            }
        }).fail(function() {
            $resultsSummaryContainer.html('<p class="ms-error">An AJAX error occurred while starting the scan.</p>');
            resetScannerUI();
        });
    }

    /**
     * Polls the server for the current scan status and updates the UI.
     */
    function updateScanStatus(initialCheck = false) {
        $.get(msAdmin.ajax_url, {
            action: 'ms_get_scan_status',
            nonce: msAdmin.nonce
        }).done(function(response) {
            if (!response.success) {
                if (initialCheck) resetScannerUI(true);
                return;
            }

            const status = response.data || {};

            if (status.status === 'running') {
                isScanning = true;
                $startFullScanButton.prop('disabled', true).text('Scanning...');
                $startQuickScanButton.prop('disabled', true);
                $('.ms-scan-controls').hide();
                $progressBar.show();
                updateProgressUI(status.progress || 0, status.scanned_files || 0, status.total_files || 0, status.issues || 0);
                if (!scanStatusInterval) {
                    scanStatusInterval = setInterval(updateScanStatus, 2000);
                }
            } else if (status.status === 'finished') {
                clearInterval(scanStatusInterval);
                scanStatusInterval = null;
                updateProgressUI(100, status.scanned_files || 0, status.total_files || 0, status.issues || 0);
                getScanResults();
            } else { // Catches 'idle' or undefined status
                clearInterval(scanStatusInterval);
                scanStatusInterval = null;
                // On initial load, if status is idle, try to get last results instead of showing "never scanned"
                if (initialCheck && status.scan_end) {
                    getScanResults();
                } else if (initialCheck) {
                    resetScannerUI(true);
                } else {
                    resetScannerUI();
                }
            }
        }).fail(function() {
            clearInterval(scanStatusInterval);
            scanStatusInterval = null;
            $resultsSummaryContainer.html('<p class="ms-error">Could not retrieve scan status.</p>');
            resetScannerUI();
        });
    }

    /**
     * Updates the progress bar and text indicators.
     */
    function updateProgressUI(progress, scanned, total, issues) {
        $progressBarInner.css('width', progress + '%');
        $progressPercentage.text(progress + '%');
        $scanProgressText.text(`${scanned} / ${total}`);
        $scanIssuesText.text(issues);
        $resultsSummaryContainer.html(`<p>Scanning file ${scanned} of ${total}...</p>`);
    }

    /**
     * Fetches and renders the final scan results.
     */
    function getScanResults() {
        $resultsSummaryContainer.html('<p>Loading final results...</p>');
        $.get(msAdmin.ajax_url, {
            action: 'ms_get_scan_results',
            nonce: msAdmin.nonce
        }).done(function(response) {
            if (response.success) {
                renderResults(response.data);
                updateSummary(response.data);
            } else {
                $resultsSummaryContainer.html(`<p class="ms-error">${response.data.message || 'Failed to load results.'}</p>`);
            }
        }).fail(function() {
            $resultsSummaryContainer.html('<p class="ms-error">An AJAX error occurred while loading results.</p>');
        }).always(function() {
            resetScannerUI();
        });
    }

    function getIssueTypeDescription(type) {
        const descriptions = {
            'CORE_FILE_MODIFIED': 'Core file has been modified.',
            'PLUGIN_FILE_MODIFIED': 'Plugin file has been modified.',
            'THEME_FILE_MODIFIED': 'Theme file has been modified.',
            'CORE_EXTRA_FILE': 'File is not part of the official WordPress distribution.',
            'PLUGIN_EXTRA_FILE': 'File is not part of the official plugin distribution.',
            'THEME_EXTRA_FILE': 'File is not part of the official theme distribution.',
            'CORE_FILE_MISSING': 'Official WordPress core file is missing.',
            'PLUGIN_FILE_MISSING': 'Official plugin file is missing.',
            'THEME_FILE_MISSING': 'Official theme file is missing.',
            'UNWANTED_EXTENSION': 'File has an extension often used for malicious purposes.',
            'MALWARE_DETECTED': 'A malware signature was found in this file.',
            'FILE_CHANGED': 'File content, size, or modification date has changed since last scan.',
            'NOT_PUBLIC_PLUGIN': 'Plugin not found on WordPress.org, cannot verify integrity.',
            'NOT_PUBLIC_THEME': 'Theme not found on WordPress.org, cannot verify integrity.',
            'NO_INTEGRITY_DATA': 'No checksums available for this version.'
        };
        return descriptions[type] || type.replace(/_/g, ' ');
    }

    function renderResults(data) {
        const { summary, issues } = data;
        let html = '';
        let totalIssues = issues.length;

        if (!summary || Object.keys(summary).length === 0) {
            html = '<div class="ms-scan-ok"><span class="dashicons dashicons-shield-alt"></span><h3>No Scan Data</h3><p>The scan did not return any data. Please try again.</p></div>';
            $resultsSummaryContainer.html(html);
            return;
        }

        const renderSection = (sectionTitle, sectionData, sectionKey) => {
            if (!sectionData) return;
            html += `<h3>${sectionTitle}</h3>`;
            for (const slug in sectionData) {
                const item = sectionData[slug];
                const itemIssues = issues.filter(i => {
                    if (sectionKey === 'core') return i.issue_type.startsWith('CORE');
                    if (sectionKey === 'plugins') return i.file_path.startsWith(`wp-content/plugins/${slug}`);
                    if (sectionKey === 'themes') return i.file_path.startsWith(`wp-content/themes/${slug}`);
                    return false;
                });
                html += createSummaryRow(item.name, item.status, itemIssues);
            }
        };

        renderSection('WordPress Core', { 'core': summary.core }, 'core');
        renderSection('Plugins', summary.plugins, 'plugins');
        renderSection('Themes', summary.themes, 'themes');

        if (totalIssues === 0) {
            html = '<div class="ms-scan-ok"><span class="dashicons dashicons-shield-alt"></span><h3>No Issues Found</h3><p>Congratulations! Your WordPress installation appears to be clean and secure.</p></div>';
        }

        $resultsSummaryContainer.html(html);
    }

    function createSummaryRow(name, status, issues) {
        let statusText = 'Verified';
        let statusClass = 'verified';
        let issueDetailsHtml = '';
        let rowClass = 'no-issues';

        if (status === 'issues_found' && issues.length > 0) {
            statusText = `Issues Found (${issues.length})`;
            statusClass = 'issues-found';
            rowClass = 'has-issues';

            let tableRows = '';
            issues.forEach(item => {
                let actions = '';
                if (item.issue_type === 'CORE_FILE_MODIFIED' || item.issue_type === 'MALWARE_DETECTED' || item.issue_type === 'CORE_EXTRA_FILE') {
                    actions += `<button class="button button-small ms-quarantine-file" data-file="${item.file_path}">Quarantine</button> `;
                }
                if (item.issue_type === 'CORE_FILE_MODIFIED') {
                    actions += `<button class="button button-primary button-small ms-repair-file" data-file="${item.file_path}">Repair</button> `;
                    actions += `<button class="button button-small ms-view-diff" data-file="${item.file_path}">View Diff</button>`;
                }

                tableRows += `<tr data-file-path="${item.file_path}">
                    <td><code>${item.file_path}</code></td>
                    <td>${getIssueTypeDescription(item.issue_type)}</td>
                    <td>${item.details || 'N/A'}</td>
                    <td class="ms-actions-cell">${actions || 'No actions available'}</td>
                </tr>`;
            });

            issueDetailsHtml = `<div class="ms-issue-details-container" style="display:none;">
                <table class="wp-list-table widefat striped">
                    <thead>
                        <tr><th>File Path</th><th>Issue</th><th>Details</th><th>Actions</th></tr>
                    </thead>
                    <tbody>${tableRows}</tbody>
                </table>
            </div>`;
        }

        return `<div>
            <div class="ms-summary-row ${rowClass}">
                <div class="ms-summary-name">${name}</div>
                <div class="ms-summary-status"><span class="ms-status-badge ${statusClass}">${statusText}</span></div>
            </div>
            ${issueDetailsHtml}
        </div>`;
    }

    function updateSummary(data) {
        const { summary, scan_start, scan_end } = data;
        if (!summary) return;

        let totalIssues = 0;
        if (summary.core) totalIssues += summary.core.issues;
        if (summary.plugins) Object.values(summary.plugins).forEach(p => totalIssues += p.issues);
        if (summary.themes) Object.values(summary.themes).forEach(t => totalIssues += t.issues);

        $('#ms-scan-started').text(new Date(scan_start * 1000).toLocaleString());
        $('#ms-scan-finished').text(new Date(scan_end * 1000).toLocaleString());
        const duration = scan_end - scan_start;
        $('#ms-scan-duration').text(`${duration}s`);
        $('#ms-scan-issues-text').text(totalIssues);
    }

    function resetScannerUI(isInitialLoad = false) {
        isScanning = false;
        $startFullScanButton.prop('disabled', false).text('Start Full Scan');
        $startQuickScanButton.prop('disabled', false);
        $('.ms-scan-controls').show();
        $progressBar.hide();
        if (isInitialLoad) {
            $resultsSummaryContainer.html('<p>This website has never been scanned. To start scanning click the button below.</p>');
        }
    }

    function showDiffModal(content) {
        if ($('#ms-diff-modal').length === 0) {
            $('body').append(`
                <div class="ms-diff-modal-backdrop"></div>
                <div id="ms-diff-modal" class="ms-diff-modal">
                    <div class="ms-diff-modal-header">
                        <h3>File Differences</h3>
                        <button class="ms-diff-modal-close">&times;</button>
                    </div>
                    <div class="ms-diff-modal-body"></div>
                </div>
            `);
        }
        $('.ms-diff-modal-body').html(content);
        $('.ms-diff-modal-backdrop, #ms-diff-modal').fadeIn(200);
    }

    function closeDiffModal() {
        $('.ms-diff-modal-backdrop, #ms-diff-modal').fadeOut(200);
    }

    // --- Event Handlers ---
    $startFullScanButton.on('click', () => startScan('full'));
    $startQuickScanButton.on('click', () => startScan('quick'));

    // Warn user before leaving page if scan is running
    $(window).on('beforeunload', function() {
        if (isScanning) {
            return 'A scan is in progress. Closing the page will not stop the scan, which will continue in the background.';
        }
    });

    $resultsSummaryContainer.on('click', '.ms-summary-row.has-issues', function() {
        $(this).next('.ms-issue-details-container').slideToggle(200);
    });

    $resultsSummaryContainer.on('click', '.ms-repair-file', function(e) {
        e.stopPropagation();
        const $button = $(this);
        const filePath = $button.data('file');
        if (confirm('Are you sure you want to repair this file: ' + filePath + '? This will replace it with the official version.')) {
            $button.prop('disabled', true).text('Repairing...');
            $.post(msAdmin.ajax_url, { action: 'ms_repair_core_file', nonce: msAdmin.nonce, file_path: filePath })
                .done(response => {
                    if (response.success) {
                        $button.closest('tr').css('background-color', '#d4edda').find('td').eq(1).text('Repaired');
                        $button.parent().html('<em>Repaired</em>');
                    } else {
                        alert(response.data.message || 'Failed to repair file.');
                        $button.prop('disabled', false).text('Repair');
                    }
                })
                .fail(() => {
                    alert('An AJAX error occurred.');
                    $button.prop('disabled', false).text('Repair');
                });
        }
    });

    $resultsSummaryContainer.on('click', '.ms-view-diff', function(e) {
        e.stopPropagation();
        const $button = $(this);
        const filePath = $button.data('file');
        $button.prop('disabled', true).text('Loading...');
        $.post(msAdmin.ajax_url, { action: 'ms_get_file_diff', nonce: msAdmin.nonce, file_path: filePath })
            .done(response => response.success ? showDiffModal(response.data.diff) : alert(response.data.message || 'Failed to get diff.'))
            .fail(() => alert('An AJAX error occurred.'))
            .always(() => $button.prop('disabled', false).text('View Diff'));
    });

    $(document).on('click', '.ms-diff-modal-close, .ms-diff-modal-backdrop', closeDiffModal);

    // --- Initial Load ---
    setupTabNavigation();
    updateScanStatus(true); // Pass true for initial check
});
