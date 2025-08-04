document.addEventListener('DOMContentLoaded', function() {
    const tabs = document.querySelectorAll('.nav-tab-wrapper a.nav-tab');
    const tabContents = document.querySelectorAll('.tab-content');
    const formProtectionRadios = document.querySelectorAll('input[name="ms_form_protection_service"]');
    const recaptchaWrapper = document.getElementById('recaptcha-settings-wrapper');
    const turnstileWrapper = document.getElementById('turnstile-settings-wrapper');

    // --- Tab Switching Logic ---
    function activateTab(tab) {
        tabs.forEach(t => t.classList.remove('nav-tab-active'));
        tab.classList.add('nav-tab-active');

        tabContents.forEach(c => c.style.display = 'none');
        const activeContent = document.querySelector(tab.getAttribute('href'));
        if (activeContent) {
            activeContent.style.display = 'block';
        }
    }

    tabs.forEach(tab => {
        tab.addEventListener('click', function(e) {
            e.preventDefault();
            activateTab(this);
            // Store the active tab in localStorage
            localStorage.setItem('msActiveAntiSpamTab', this.getAttribute('href'));
        });
    });

    // --- Form Protection Logic ---
    function toggleProtectionSections() {
        const selectedService = document.querySelector('input[name="ms_form_protection_service"]:checked').value;

        if (recaptchaWrapper) {
            recaptchaWrapper.style.display = (selectedService === 'recaptcha') ? 'block' : 'none';
        }
        if (turnstileWrapper) {
            turnstileWrapper.style.display = (selectedService === 'turnstile') ? 'block' : 'none';
        }
    }

    formProtectionRadios.forEach(radio => {
        radio.addEventListener('change', toggleProtectionSections);
    });

    // --- Initialization ---
    // Restore the last active tab or default to the first one
    const lastTab = localStorage.getItem('msActiveAntiSpamTab');
    const tabToActivate = document.querySelector(`.nav-tab-wrapper a[href="${lastTab}"]`) || tabs[0];

    if (tabToActivate) {
        activateTab(tabToActivate);
    }

    // Initial check for form protection sections
    toggleProtectionSections();
});
