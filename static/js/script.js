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
            return;
        }
        const data = await response.json();

        if (data.error) {
             console.error('Error from chart_data endpoint:', data.error);
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
                        label: '# Times Flagged', // Shortened label
                        data: data.label_values,
                        backgroundColor: [
                            'rgba(220, 53, 69, 0.7)',  // Danger Red
                            'rgba(255, 193, 7, 0.7)',  // Warning Orange
                            'rgba(220, 53, 69, 0.7)'   // Danger Red (Bias)
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
                    // indexAxis: 'y', // Keep as vertical bar chart
                    scales: {
                        y: { // Y-axis is value axis for vertical bar
                            beginAtZero: true,
                             ticks: { stepSize: 1, precision: 0 } // Ensure integer steps
                        }
                    },
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }, // Keep legend off for bar
                        title: { display: true, text: 'Count of Specific Issues Flagged' } // Add title
                     }
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
            const all_flags_order = ['Red', 'Orange', 'Green', 'White']; // Consistent order for colors
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

            // Filter data to avoid showing 0-count slices in the pie chart
            const filteredData = { flags: [], values: [], bgColors: [], borderColors: [] };
            let totalValue = 0;
            data.flags.forEach((flag, index) => {
                const value = data.flag_values[index];
                totalValue += value;
                if (value > 0) {
                    const colorIndex = all_flags_order.indexOf(flag);
                    if (colorIndex !== -1) {
                        filteredData.flags.push(flag);
                        filteredData.values.push(value);
                        filteredData.bgColors.push(flagBackgroundColors[colorIndex]);
                        filteredData.borderColors.push(flagBorderColors[colorIndex]);
                    }
                }
            });

            // Handle case where there's no data at all
            if (totalValue === 0) {
                filteredData.flags = ['No Data'];
                filteredData.values = [1];
                filteredData.bgColors = ['rgba(220, 220, 220, 0.7)']; // Gray for no data
                filteredData.borderColors = ['rgba(180, 180, 180, 1)'];
            }


            flagPieChartInstance = new Chart(pieCtx, {
                type: 'pie',
                data: {
                    labels: filteredData.flags,
                    datasets: [{
                        label: 'Flags', // Shorter label
                        data: filteredData.values,
                        backgroundColor: filteredData.bgColors,
                        borderColor: filteredData.borderColors,
                        borderWidth: 1
                    }]
                },
                 options: {
                    responsive: true,
                    maintainAspectRatio: false,
                     plugins: {
                         legend: {
                            position: 'top', // Legend position
                            labels: { padding: 15 } // Add padding to legend items
                         },
                         title: { display: true, text: 'Distribution of Overall Risk Flags' }, // Add title
                         tooltip: {
                              callbacks: {
                                label: function(context) {
                                    if (context.label === 'No Data') return null; // Hide tooltip for "No Data"

                                    let label = context.label || '';
                                    if (label) label += ': ';
                                    const value = context.parsed || 0;
                                    label += value;

                                    // Calculate percentage using the *original* total count if needed, or filtered total
                                    // Using filtered total for percentage of shown slices:
                                     const filteredTotal = context.dataset.data.reduce((a, b) => a + b, 0);
                                     const percentage = filteredTotal > 0 ? Math.round((value / filteredTotal) * 100) : 0;
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