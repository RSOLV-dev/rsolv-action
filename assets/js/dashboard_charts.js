// Enhanced chart visualization using Chart.js
// Using Chart.js from vendor directory
import Chart from '../vendor/chart/chart.js';

// Define chart hooks for Phoenix LiveView
const Hooks = {
  // Generic line chart for time series data
  SimpleChart: {
    mounted() {
      try {
        this.initChart();

        // Handle data updates
        this.handleEvent("updateChartData", (data) => {
          this.updateChart(data);
        });
      } catch (error) {
        console.error("Error mounting SimpleChart:", error);
        this.displayErrorState("Failed to initialize chart");
      }
    },

    updated() {
      try {
        if (this.chart) {
          this.chart.destroy();
        }
        this.initChart();
      } catch (error) {
        console.error("Error updating SimpleChart:", error);
        this.displayErrorState("Failed to update chart");
      }
    },

    initChart() {
      try {
        const ctx = this.el.getContext('2d');
        let chartData = [];
        
        try {
          chartData = JSON.parse(this.el.dataset.chartdata || '[]');
          // Check if data is empty or invalid
          if (!chartData || !Array.isArray(chartData) || chartData.length === 0) {
            this.displayEmptyState("No data available for this period");
            return;
          }
        } catch (parseError) {
          console.error("Error parsing chart data:", parseError);
          this.displayErrorState("Invalid chart data");
          return;
        }
        
        // Group data by label with error handling
        const datasets = Object.entries(
          chartData.reduce((acc, item) => {
            try {
              const label = item.label || 'Value';
              if (!acc[label]) {
                acc[label] = [];
              }
              
              // Validate date and count
              if (item.date && (typeof item.count === 'number' || typeof item.count === 'string')) {
                acc[label].push(item);
              }
              return acc;
            } catch (error) {
              console.warn("Error processing chart item:", error, item);
              return acc;
            }
          }, {})
        ).map(([label, data]) => ({
          label,
          data: data.map(d => ({ 
            x: d.date, 
            y: typeof d.count === 'string' ? parseInt(d.count) : d.count
          })),
          borderColor: getColorForLabel(label),
          tension: 0.1,
          fill: false,
          pointRadius: 3,
          pointHoverRadius: 5
        }));
        
        // Check if we have valid datasets after processing
        if (datasets.length === 0 || datasets.every(d => d.data.length === 0)) {
          this.displayEmptyState("No valid data points for this period");
          return;
        }
        
        // Create chart with improved styling and error handling
        this.chart = new Chart(ctx, {
          type: 'line',
          data: {
            datasets
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
              duration: 500
            },
            interaction: {
              mode: 'index',
              intersect: false
            },
            scales: {
              x: {
                type: 'time',
                time: {
                  unit: 'day',
                  tooltipFormat: 'MMM d, yyyy'
                },
                title: {
                  display: true,
                  text: 'Date'
                },
                grid: {
                  color: 'rgba(0, 0, 0, 0.05)'
                }
              },
              y: {
                beginAtZero: true,
                title: {
                  display: true,
                  text: 'Count'
                },
                grid: {
                  color: 'rgba(0, 0, 0, 0.05)'
                }
              }
            },
            plugins: {
              tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.7)',
                titleFont: {
                  weight: 'bold'
                }
              },
              legend: {
                position: 'top',
                labels: {
                  boxWidth: 12,
                  usePointStyle: true
                }
              }
            }
          }
        });
      } catch (error) {
        console.error("Error initializing chart:", error);
        this.displayErrorState("Error creating chart");
      }
    },

    updateChart(data) {
      try {
        if (this.chart) {
          this.chart.data.datasets = data.datasets;
          this.chart.update();
        }
      } catch (error) {
        console.error("Error updating chart data:", error);
      }
    },
    
    // Display an empty state message in the chart area
    displayEmptyState(message) {
      this.clearCanvas();
      const ctx = this.el.getContext('2d');
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '14px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#6B7280'; // gray-500
      ctx.fillText(message || 'No data available', this.el.width / 2, this.el.height / 2);
    },
    
    // Display an error state message in the chart area
    displayErrorState(message) {
      this.clearCanvas();
      const ctx = this.el.getContext('2d');
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '14px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#EF4444'; // red-500
      ctx.fillText(message || 'Error loading chart data', this.el.width / 2, this.el.height / 2);
    },
    
    // Clear the canvas for custom messages
    clearCanvas() {
      const canvas = this.el;
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
  },

  // Bar chart for categorical data
  BarChart: {
    mounted() {
      try {
        this.initChart();
      } catch (error) {
        console.error("Error mounting BarChart:", error);
        this.displayErrorState("Failed to initialize chart");
      }
    },

    updated() {
      try {
        if (this.chart) {
          this.chart.destroy();
        }
        this.initChart();
      } catch (error) {
        console.error("Error updating BarChart:", error);
        this.displayErrorState("Failed to update chart");
      }
    },

    initChart() {
      try {
        const ctx = this.el.getContext('2d');
        let chartData = [];
        
        try {
          chartData = JSON.parse(this.el.dataset.chartdata || '[]');
          // Check if data is empty or invalid
          if (!chartData || !Array.isArray(chartData) || chartData.length === 0) {
            this.displayEmptyState("No data available for this period");
            return;
          }
        } catch (parseError) {
          console.error("Error parsing chart data:", parseError);
          this.displayErrorState("Invalid chart data");
          return;
        }
        
        // Extract labels and values with validation
        const labels = [];
        const values = [];
        
        chartData.forEach(item => {
          try {
            // Get the category (with fallbacks)
            let category;
            if (Array.isArray(item)) {
              category = item[0] || 'Unknown';
            } else {
              category = item.source || item.key || item.name || 'Unknown';
            }
            
            // Get the value (with fallbacks and type safety)
            let value;
            if (Array.isArray(item)) {
              value = item[1];
              if (typeof value === 'string') {
                value = parseFloat(value) || 0;
              }
            } else {
              value = item.count || item.value || 0;
              if (typeof value === 'string') {
                value = parseFloat(value) || 0;
              }
            }
            
            // Only add valid data points
            if (category && value !== undefined) {
              // Truncate long labels
              const displayLabel = category.length > 20 ? category.substring(0, 17) + '...' : category;
              labels.push(displayLabel);
              values.push(value);
            }
          } catch (itemError) {
            console.warn("Error processing bar chart item:", itemError, item);
          }
        });
        
        // Check if we have valid data after processing
        if (labels.length === 0 || values.length === 0) {
          this.displayEmptyState("No valid data points for this period");
          return;
        }
        
        // Create chart with improved styling
        this.chart = new Chart(ctx, {
          type: 'bar',
          data: {
            labels,
            datasets: [{
              label: 'Count',
              data: values,
              backgroundColor: generateColors(values.length),
              borderWidth: 1,
              borderRadius: 4,
              borderColor: 'rgba(0, 0, 0, 0.1)'
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
              duration: 500
            },
            plugins: {
              legend: {
                display: false
              },
              tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.7)',
                callbacks: {
                  label: function(context) {
                    return ` ${context.parsed.y}`;
                  }
                }
              }
            },
            scales: {
              y: {
                beginAtZero: true,
                grid: {
                  color: 'rgba(0, 0, 0, 0.05)'
                }
              },
              x: {
                grid: {
                  display: false
                }
              }
            }
          }
        });
      } catch (error) {
        console.error("Error initializing bar chart:", error);
        this.displayErrorState("Error creating chart");
      }
    },
    
    // Display an empty state message in the chart area
    displayEmptyState(message) {
      this.clearCanvas();
      const ctx = this.el.getContext('2d');
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '14px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#6B7280'; // gray-500
      ctx.fillText(message || 'No data available', this.el.width / 2, this.el.height / 2);
    },
    
    // Display an error state message in the chart area
    displayErrorState(message) {
      this.clearCanvas();
      const ctx = this.el.getContext('2d');
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '14px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#EF4444'; // red-500
      ctx.fillText(message || 'Error loading chart data', this.el.width / 2, this.el.height / 2);
    },
    
    // Clear the canvas for custom messages
    clearCanvas() {
      const canvas = this.el;
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
  },

  // Pie chart for distribution data
  PieChart: {
    mounted() {
      try {
        this.initChart();
      } catch (error) {
        console.error("Error mounting PieChart:", error);
        this.displayErrorState("Failed to initialize chart");
      }
    },

    updated() {
      try {
        if (this.chart) {
          this.chart.destroy();
        }
        this.initChart();
      } catch (error) {
        console.error("Error updating PieChart:", error);
        this.displayErrorState("Failed to update chart");
      }
    },

    initChart() {
      try {
        const ctx = this.el.getContext('2d');
        let chartData = [];
        
        try {
          chartData = JSON.parse(this.el.dataset.chartdata || '[]');
          // Check if data is empty or invalid
          if (!chartData || !Array.isArray(chartData) || chartData.length === 0) {
            this.displayEmptyState("No data available for this period");
            return;
          }
        } catch (parseError) {
          console.error("Error parsing chart data:", parseError);
          this.displayErrorState("Invalid chart data");
          return;
        }
        
        // Extract labels and values with validation
        const labels = [];
        const values = [];
        
        chartData.forEach(item => {
          try {
            // Skip items with zero values to avoid cluttering the pie chart
            const value = item.count || item.value || 0;
            if (value <= 0) return;
            
            const label = item.source || item.key || 'Unknown';
            labels.push(label);
            values.push(value);
          } catch (itemError) {
            console.warn("Error processing pie chart item:", itemError, item);
          }
        });
        
        // Check if we have valid data after processing
        if (labels.length === 0 || values.length === 0) {
          this.displayEmptyState("No valid data points for this period");
          return;
        }
        
        // Create chart with improved styling
        this.chart = new Chart(ctx, {
          type: 'pie',
          data: {
            labels,
            datasets: [{
              data: values,
              backgroundColor: generateColors(values.length),
              borderColor: 'white',
              borderWidth: 1,
              hoverOffset: 10
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
              duration: 500
            },
            plugins: {
              legend: {
                position: 'right',
                labels: {
                  boxWidth: 15,
                  padding: 15,
                  generateLabels: function(chart) {
                    const labels = Chart.defaults.plugins.legend.labels.generateLabels(chart);
                    
                    // Limit the number of visible labels to avoid cluttering
                    if (labels.length > 7) {
                      const topLabels = labels.slice(0, 5);
                      const otherValue = labels.slice(5).reduce((sum, label) => {
                        const value = chart.data.datasets[0].data[label.index];
                        return sum + (value || 0);
                      }, 0);
                      
                      if (otherValue > 0) {
                        topLabels.push({
                          text: 'Other',
                          fillStyle: '#CBD5E1', // slate-300
                          strokeStyle: '#CBD5E1',
                          lineWidth: 1,
                          hidden: false
                        });
                      }
                      
                      return topLabels;
                    }
                    
                    return labels;
                  }
                }
              },
              tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.7)',
                callbacks: {
                  label: function(context) {
                    const label = context.label || '';
                    const value = context.raw || 0;
                    const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                    const percentage = Math.round((value / total) * 100);
                    return ` ${label}: ${value} (${percentage}%)`;
                  }
                }
              }
            }
          }
        });
      } catch (error) {
        console.error("Error initializing pie chart:", error);
        this.displayErrorState("Error creating chart");
      }
    },
    
    // Display an empty state message in the chart area
    displayEmptyState(message) {
      this.clearCanvas();
      const ctx = this.el.getContext('2d');
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '14px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#6B7280'; // gray-500
      ctx.fillText(message || 'No data available', this.el.width / 2, this.el.height / 2);
    },
    
    // Display an error state message in the chart area
    displayErrorState(message) {
      this.clearCanvas();
      const ctx = this.el.getContext('2d');
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '14px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#EF4444'; // red-500
      ctx.fillText(message || 'Error loading chart data', this.el.width / 2, this.el.height / 2);
    },
    
    // Clear the canvas for custom messages
    clearCanvas() {
      const canvas = this.el;
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
  }
};

// Helper function to generate colors with improved palette
function generateColors(count) {
  const colors = [
    '#3B82F6', // blue-500
    '#10B981', // emerald-500
    '#F59E0B', // amber-500
    '#8B5CF6', // violet-500
    '#EF4444', // red-500
    '#06B6D4', // cyan-500
    '#F97316', // orange-500
    '#6366F1', // indigo-500
    '#EC4899', // pink-500
    '#14B8A6'  // teal-500
  ];
  
  // If we need more colors than in our array, repeat them with opacity variation
  if (count <= colors.length) {
    return colors.slice(0, count);
  }
  
  const result = [];
  for (let i = 0; i < count; i++) {
    const baseColor = colors[i % colors.length];
    // For repeated colors, add subtle variations in opacity
    if (i >= colors.length) {
      const opacity = 0.7 - (0.1 * Math.floor(i / colors.length));
      const rgba = hexToRgba(baseColor, Math.max(0.4, opacity));
      result.push(rgba);
    } else {
      result.push(baseColor);
    }
  }
  
  return result;
}

// Helper function to convert hex color to rgba
function hexToRgba(hex, alpha = 1) {
  // Remove the hash if it exists
  hex = hex.replace('#', '');
  
  // Parse the hex values
  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);
  
  // Return as rgba
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

// Helper function to get color for a specific label
function getColorForLabel(label) {
  const colorMap = {
    'Visitors': '#3B82F6',     // blue-500
    'Conversions': '#10B981',  // emerald-500
    'Signups': '#F59E0B',      // amber-500
    'Downloads': '#8B5CF6',    // violet-500
    'Sessions': '#06B6D4',     // cyan-500
    'Pageviews': '#F97316'     // orange-500
  };
  
  return colorMap[label] || '#3B82F6'; // Default to blue
}

export default Hooks;