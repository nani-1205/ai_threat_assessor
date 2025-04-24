// static/js/script.js

let labelBarChartInstance = null;
let flagPieChartInstance = null;

// Function to fetch data and update charts
async function updateCharts() {
    console.log("Fetching chart data...");
    try {
        const response = await fetch('/chart_data');
        if (!response.ok) {
            console.error('Failed to fetch chart data:', response.status, response.statusText);
            // Optionally display an error to the user on the page
            return;
        }
        const data = await response.json();

        if (data.error) {
             console.error('Error from chart_data endpoint:', data.error);
             // Optionally display an error to the user
             return;
        }
        console.log("Chart data received:", data);


        // --- Update Label Bar Chart ---
        const barCtx = document.getElementById('labelBarChart')?.getContext('2d');
        if (barCtx) {
             console.log("Updating Label Bar Chart");
             if (labelBarChartInstance) {
                labelBarChartInstance.destroy();
            }
            labelBarChartInstance = new Chart(barCtx, {
                type: 'bar',
                data: {
                    labels: data.labels, // ['Humanity Threatening', 'Bypasses EU Laws', 'Gender Biased']
                    datasets: [{
                        label: '# of Times Flagged in Evaluation',
                        data: data.label_values,
                        backgroundColor: [
                            'rgba(220, 53, 69, 0.6)',  // Danger Red
                            'rgba(255, 193, 7, 0.6)',  // Warning Orange
                            'rgba(220, 53, 69, 0.6)'   // Danger Red (Consider distinct color for bias if needed)
                        ],
                        borderColor: [
                            'rgba(220, 53, 69, 1)',
                            'rgba(255, 193, 7, 1)',
                            'rgba(220, 53, 69, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    indexAxis: 'y', // Optional: makes labels easier to read if long
                    scales: {
                        x: { // Changed from y for horizontal bars if indexAxis is 'y'
                            beginAtZero: true,
                             ticks: { stepSize: 1, precision: 0 } // Ensure integer steps
                        }
                    },
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } }
                }
            });
        } else {
             console.warn("Canvas element for labelBarChart not found.");
        }


        // --- Update Flag Pie Chart ---
        const pieCtx = document.getElementById('flagPieChart')?.getContext('2d');
         if (pieCtx) {
             console.log("Updating Flag Pie Chart");
            if (flagPieChartInstance) {
                flagPieChartInstance.destroy();
            }
            // Define colors matching the order from backend: ['Red', 'Orange', 'Green', 'White']
            const flagBackgroundColors = [
                 'rgba(220, 53, 69, 0.7)', // Red
                 'rgba(255, 193, 7, 0.7)',  // Orange
                 'rgba(25, 135, 84, 0.7)',  // Green
                 'rgba(200, 200, 200, 0.7)' // White/Gray
            ];
             const flagBorderColors = [
                 'rgba(220, 53, 69, 1)',
                 'rgba(255, 193, 7, 1)',
                 'rgba(25, 135, 84, 1)',
                 'rgba(150, 150, 150, 1)'
            ];

            // Filter data to only include flags with count > 0 if desired for cleaner pie chart
            const filteredFlags = data.flags.filter((_, index) => data.flag_values[index] > 0);
            const filteredValues = data.flag_values.filter(value => value > 0);
            const filteredBgColors = data.flags.map((flag, index) => data.flag_values[index] > 0 ? flagBackgroundColors[all_flags_order.indexOf(flag)] : null).filter(color => color !== null);
            const filteredBorderColors = data.flags.map((flag, index) => data.flag_values[index] > 0 ? flagBorderColors[all_flags_order.indexOf(flag)] : null).filter(color => color !== null);
            const all_flags_order = ['Red', 'Orange', 'Green', 'White']; // Ensure consistent color mapping


            flagPieChartInstance = new Chart(pieCtx, {
                type: 'pie',
                data: {
                    labels: filteredFlags.length > 0 ? filteredFlags : ['No Data'], // Use filtered data
                    datasets: [{
                        label: 'Overall Risk Flags',
                        data: filteredValues.length > 0 ? filteredValues : [1], // Use filtered data
                        backgroundColor: filteredBgColors.length > 0 ? filteredBgColors : ['rgba(200, 200, 200, 0.7)'], // Default color if no data
                        borderColor: filteredBorderColors.length > 0 ? filteredBorderColors : ['rgba(150, 150, 150, 1)'],
                        borderWidth: 1
                    }]
                },
                 options: {
                    responsive: true,
                    maintainAspectRatio: false,
                     plugins: {
                         legend: { position: 'top', },
                         tooltip: {
                              callbacks: {
                                label: function(context) {
                                    // Avoid showing tooltip for 'No Data' slice
                                    if (context.label === 'No Data') return null;

                                    let label = context.label || '';
                                    if (label) label += ': ';
                                    if (context.parsed !== null) label += context.parsed;
                                     const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                     const percentage = total > 0 ? Math.round((context.parsed / total) * 100) : 0;
                                     label += ` (${percentage}%)`;
                                    return label;
                                }
                            }
                         }
                     }
                 }
            });
         } else {
             console.warn("Canvas element for flagPieChart not found.");
         }

    } catch (error) {
        console.error('Error fetching or processing chart data:', error);
    }
}

// Function to be called when the DOM is ready
function initializeCharts() {
    console.log("Initializing charts...");
    updateCharts(); // Initial load
}

// Called from inline script in index.html