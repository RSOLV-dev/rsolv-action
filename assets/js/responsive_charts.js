/**
 * responsive_charts.js
 * Enhanced Chart.js hooks with responsive design for mobile devices
 */
import Chart from '../vendor/chart/chart.js';

const ResponsiveChartHooks = {
  SimpleChart: {
    mounted() {
      this.setupChart();
      
      // Add resize handler for responsive charts
      this.resizeObserver = new ResizeObserver(entries => {
        for (let entry of entries) {
          if (this.chart) {
            this.chart.resize();
          }
        }
      });
      
      this.resizeObserver.observe(this.el);
      
      // Handle mobile orientation changes
      window.addEventListener('orientationchange', () => {
        if (this.chart) {
          // Wait for orientation change to complete
          setTimeout(() => {
            this.chart.resize();
            this.optimizeForMobile();
          }, 200);
        }
      });
    },
    
    optimizeForMobile() {
      if (!this.chart) return;
      
      // Check if we're on a small screen
      const isMobile = window.innerWidth < 768;
      
      if (isMobile) {
        // Simplify the chart for mobile
        this.chart.options.plugins.legend.display = false;
        this.chart.options.scales.x.ticks.maxRotation = 45;
        this.chart.options.scales.x.ticks.autoSkip = true;
        this.chart.options.scales.x.ticks.autoSkipPadding = 10;
        
        // Show fewer labels on mobile
        if (this.chart.options.scales.x.ticks.callback) {
          const originalCallback = this.chart.options.scales.x.ticks.callback;
          this.chart.options.scales.x.ticks.callback = function(value, index) {
            // On mobile, only show every nth label
            return index % 3 === 0 ? originalCallback(value, index) : '';
          };
        }
      } else {
        // Reset to default for larger screens
        this.chart.options.plugins.legend.display = true;
        this.chart.options.scales.x.ticks.maxRotation = 0;
        
        // Restore original callback if it exists
        if (this.chart._originalTickCallback) {
          this.chart.options.scales.x.ticks.callback = this.chart._originalTickCallback;
        }
      }
      
      this.chart.update();
    },
    
    setupChart() {
      try {
        const data = JSON.parse(this.el.dataset.chartdata);
        const ctx = this.el.getContext('2d');
        
        // Store original dimensions for responsive sizing
        this.originalWidth = this.el.width;
        this.originalHeight = this.el.height;
        
        // Create chart with responsive option
        this.chart = new Chart(ctx, {
          type: 'line',
          data: {
            labels: data.map(d => d.label),
            datasets: [{
              label: data[0]?.dataset || 'Data',
              data: data.map(d => d.value),
              borderColor: '#3B82F6',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.2
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                display: window.innerWidth >= 768, // Only show legend on larger screens
                position: 'top',
              },
              tooltip: {
                enabled: true,
                mode: 'index',
                intersect: false,
                callbacks: {
                  label: function(context) {
                    return `${context.dataset.label}: ${context.raw}`;
                  }
                }
              }
            },
            scales: {
              x: {
                grid: {
                  display: false
                },
                ticks: {
                  autoSkip: true,
                  maxTicksLimit: window.innerWidth < 768 ? 5 : 10 // Fewer ticks on mobile
                }
              },
              y: {
                beginAtZero: true,
                ticks: {
                  precision: 0
                }
              }
            },
            elements: {
              point: {
                radius: window.innerWidth < 768 ? 0 : 3, // Hide points on mobile
                hoverRadius: 5
              }
            },
            interaction: {
              mode: 'nearest',
              axis: 'x',
              intersect: false
            }
          }
        });
        
        // Store the chart instance for later access
        this.el._chart = this.chart;
        
        // Apply mobile optimizations
        this.optimizeForMobile();
      } catch (e) {
        console.error("Error creating chart:", e);
        // Display error message in the chart container
        this.el.innerHTML = `<div class="flex items-center justify-center h-full w-full bg-red-50 text-red-700 rounded p-4">
          <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
          </svg>
          Chart data unavailable
        </div>`;
      }
    },
    
    destroyed() {
      if (this.chart) {
        this.chart.destroy();
      }
      if (this.resizeObserver) {
        this.resizeObserver.disconnect();
      }
      window.removeEventListener('orientationchange', this.orientationChangeHandler);
    }
  },
  
  // Similar optimization for PieChart
  PieChart: {
    mounted() {
      this.setupChart();
      
      // Add resize handler for responsive charts
      this.resizeObserver = new ResizeObserver(entries => {
        for (let entry of entries) {
          if (this.chart) {
            this.chart.resize();
          }
        }
      });
      
      this.resizeObserver.observe(this.el);
    },
    
    setupChart() {
      try {
        const data = JSON.parse(this.el.dataset.chartdata);
        const ctx = this.el.getContext('2d');
        
        // Extract labels and values
        const labels = data.map(d => d.label);
        const values = data.map(d => d.value);
        
        // Generate colors based on the number of data points
        const colors = this.generateColors(data.length);
        
        this.chart = new Chart(ctx, {
          type: 'pie',
          data: {
            labels: labels,
            datasets: [{
              data: values,
              backgroundColor: colors,
              borderColor: colors.map(c => c.replace('0.7', '1')),
              borderWidth: 1
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: window.innerWidth < 768 ? 'bottom' : 'right',
                display: true,
                labels: {
                  boxWidth: window.innerWidth < 768 ? 10 : 20,
                  padding: window.innerWidth < 768 ? 5 : 10,
                  font: {
                    size: window.innerWidth < 768 ? 10 : 12
                  }
                }
              },
              tooltip: {
                callbacks: {
                  label: function(context) {
                    const label = context.label || '';
                    const value = context.raw || 0;
                    const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                    const percentage = ((value / total) * 100).toFixed(1);
                    return `${label}: ${value} (${percentage}%)`;
                  }
                }
              }
            }
          }
        });
        
        // Store the chart instance for later access
        this.el._chart = this.chart;
      } catch (e) {
        console.error("Error creating pie chart:", e);
        this.el.innerHTML = `<div class="flex items-center justify-center h-full w-full bg-red-50 text-red-700 rounded p-4">
          <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
          </svg>
          Chart data unavailable
        </div>`;
      }
    },
    
    generateColors(count) {
      // Base colors that work well together
      const baseColors = [
        'rgba(59, 130, 246, 0.7)',  // Blue
        'rgba(16, 185, 129, 0.7)',  // Green
        'rgba(245, 158, 11, 0.7)',  // Amber
        'rgba(239, 68, 68, 0.7)',   // Red
        'rgba(139, 92, 246, 0.7)',  // Purple
        'rgba(236, 72, 153, 0.7)',  // Pink
        'rgba(6, 182, 212, 0.7)',   // Cyan
        'rgba(249, 115, 22, 0.7)',  // Orange
      ];
      
      // If we need more colors than in the base set, generate additional ones
      if (count <= baseColors.length) {
        return baseColors.slice(0, count);
      } else {
        let colors = [...baseColors];
        for (let i = baseColors.length; i < count; i++) {
          const hue = (i * 137.5) % 360; // Golden angle approximation for even distribution
          colors.push(`hsla(${hue}, 70%, 60%, 0.7)`);
        }
        return colors;
      }
    },
    
    destroyed() {
      if (this.chart) {
        this.chart.destroy();
      }
      if (this.resizeObserver) {
        this.resizeObserver.disconnect();
      }
    }
  },
  
  // FunnelChart with mobile optimization
  FunnelChart: {
    mounted() {
      this.setupChart();
      window.addEventListener('resize', this.handleResize.bind(this));
    },
    
    handleResize() {
      if (this.chart) {
        this.chart.resize();
        this.optimizeForMobile();
      }
    },
    
    optimizeForMobile() {
      if (!this.chart) return;
      
      const isMobile = window.innerWidth < 768;
      
      if (isMobile) {
        // Adjust for mobile view
        this.chart.options.indexAxis = 'y'; // Horizontal bars on mobile
        this.chart.options.maintainAspectRatio = false;
        this.chart.options.plugins.legend.display = false;
      } else {
        // Reset for desktop
        this.chart.options.indexAxis = 'x'; // Vertical bars on desktop
        this.chart.options.plugins.legend.display = true;
      }
      
      this.chart.update();
    },
    
    setupChart() {
      try {
        const data = JSON.parse(this.el.dataset.chartdata);
        const ctx = this.el.getContext('2d');
        
        // Extract stages and values
        const stages = data.map(d => d.stage);
        const values = data.map(d => d.value);
        const percentages = data.map(d => d.percentage);
        
        // Calculate gradient colors based on position in funnel
        const colors = values.map((v, i) => {
          const percent = i / (values.length - 1);
          return `rgba(59, 130, 246, ${0.9 - percent * 0.6})`; // Fade from dark to light blue
        });
        
        const isMobile = window.innerWidth < 768;
        
        this.chart = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: stages,
            datasets: [{
              label: 'Users',
              data: values,
              backgroundColor: colors,
              borderColor: colors.map(c => c.replace(')', ', 1)')),
              borderWidth: 1
            }]
          },
          options: {
            indexAxis: isMobile ? 'y' : 'x', // Horizontal bars on mobile
            responsive: true,
            maintainAspectRatio: !isMobile,
            plugins: {
              legend: {
                display: !isMobile,
                position: 'top'
              },
              tooltip: {
                callbacks: {
                  label: function(context) {
                    const index = context.dataIndex;
                    const value = context.raw || 0;
                    const percentage = percentages[index] || 0;
                    return `Users: ${value} (${(percentage * 100).toFixed(1)}%)`;
                  }
                }
              }
            },
            scales: {
              y: {
                beginAtZero: true,
                ticks: {
                  precision: 0
                }
              }
            }
          }
        });
        
        // Store the chart instance
        this.el._chart = this.chart;
      } catch (e) {
        console.error("Error creating funnel chart:", e);
        this.el.innerHTML = `<div class="flex items-center justify-center h-full w-full bg-red-50 text-red-700 rounded p-4">
          <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
          </svg>
          Funnel data unavailable
        </div>`;
      }
    },
    
    destroyed() {
      if (this.chart) {
        this.chart.destroy();
      }
      window.removeEventListener('resize', this.handleResize);
    }
  }
};

export default ResponsiveChartHooks;