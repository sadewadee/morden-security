jQuery(document).ready(function($) {
    // Chart for country traffic
    const countryTrafficCtx = document.getElementById('countryTrafficChart');
    if (countryTrafficCtx) {
        new Chart(countryTrafficCtx, {
            type: 'doughnut',
            data: {
                labels: ['USA', 'China', 'Russia', 'Germany', 'Brazil'], // Dummy data
                datasets: [{
                    label: 'Traffic by Country',
                    data: [300, 150, 100, 80, 50], // Dummy data
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.2)',
                        'rgba(54, 162, 235, 0.2)',
                        'rgba(255, 206, 86, 0.2)',
                        'rgba(75, 192, 192, 0.2)',
                        'rgba(153, 102, 255, 0.2)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 206, 86, 1)',
                        'rgba(75, 192, 192, 1)',
                        'rgba(153, 102, 255, 1)'
                    ],
                    borderWidth: 1
                }]
            }
        });
    }

    // Handle country blocking
    $(document).on('click', '.ms-block-country', function() {
        const countryCode = $(this).data('country');
        // AJAX call to block country
        console.log('Blocking country:', countryCode);
    });

    $(document).on('click', '.ms-unblock-country', function() {
        const countryCode = $(this).data('country');
        // AJAX call to unblock country
        console.log('Unblocking country:', countryCode);
    });
});
