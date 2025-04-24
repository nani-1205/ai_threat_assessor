// static/js/script.js

let labelBarChartInstance = null;
let flagPieChartInstance = null;

// Function to fetch data and update charts
async function updateCharts() {
    try {
        const response = await fetch('/chart_data');
        if (!response.ok) {
            console.error('Failed to fetch chart data:', response.statusText);
            // Optionally display an error to the user on the page
            return;
        }
        const data = await response.json();

        // --- Update Label Bar Chart ---
        const barCtx = document.getElementById('labelBarChart')?.getContext('2d');
        if (barCtx) {
             if (labelBarChartInstance) {
                labelBarChartInstance.destroy(); // Destroy previous instance
            }
            labelBarChartInstance = new Chart(barCtx, {
                type: 'bar',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: '# of Times Labeled',
                        data: data.label_values,
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.6)', // Red (Threatening)
                            'rgba(255, 159, 64, 0.6)', // Orange (EU Laws)
                            'rgba(220, 53, 69, 0.6)'  // Red again (Biased) - Consider distinct color if needed
                        ],
                        borderColor: [
                            'rgba(255, 99, 132, 1)',
                            'rgba(255, 159, 64, 1)',
                            'rgba(220, 53, 69, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                             ticks: {
                                stepSize: 1 // Ensure integer steps for counts
                            }
                        }
                    },
                    responsive: true,
                    maintainAspectRatio: false, // Allow resizing within card
                     plugins: {
                        legend: {
                            display: false // Hide legend if labels on X-axis are clear
                        }
                    }
                }
            });
        } else {
             console.warn("Canvas element for labelBarChart not found.");
        }


        // --- Update Flag Pie Chart ---
        const pieCtx = document.getElementById('flagPieChart')?.getContext('2d');
         if (pieCtx) {
            if (flagPieChartInstance) {
                flagPieChartInstance.destroy(); // Destroy previous instance
            }
            flagPieChartInstance = new Chart(pieCtx, {
                type: 'pie',
                data: {
                    labels: data.flags, // ['Red', 'Orange', 'Green']
                    datasets: [{
                        label: 'Risk Flags Distribution',
                        data: data.flag_values,
                        backgroundColor: [
                            'rgba(220, 53, 69, 0.7)', // Red
                            'rgba(255, 193, 7, 0.7)',  // Orange
                            'rgba(25, 135, 84, 0.7)'   // Green
                        ],
                        borderColor: [
                           'rgba(220, 53, 69, 1)',
                            'rgba(255, 193, 7, 1)',
                            'rgba(25, 135, 84, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                 options: {
                    responsive: true,
                    maintainAspectRatio: false, // Allow resizing within card
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    let label = context.label || '';
                                    if (label) {
                                        label += ': ';
                                    }
                                    if (context.parsed !== null) {
                                        label += context.parsed;
                                    }
                                     // Optional: Add percentage
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

// Note: The actual call `initializeCharts` is done inline in index.html
// after the DOM is loaded to ensure canvas elements exist.