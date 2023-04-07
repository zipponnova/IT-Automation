function renderCharts(chartData) {
  // Create the "Days Since Last Seen - MDM" line chart
  createLineChart(
    'mdmLineChart',
    'Days Since Last Seen - MDM',
    chartData.line_chart_data.mdm
  );

  // Create the "Days Since Last Seen - Crowdstrike" line chart
  createLineChart(
    'crowdstrikeLineChart',
    'Days Since Last Seen - Crowdstrike',
    chartData.line_chart_data.crowdstrike
  );
}

function createLineChart(canvasId, chartTitle, chartData) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: chartData.labels,
      datasets: chartData.datasets,
    },
    options: {
      responsive: true,
      title: {
        display: true,
        text: chartTitle,
      },
      tooltips: {
        mode: 'index',
        intersect: false,
      },
      hover: {
        mode: 'nearest',
        intersect: true,
      },
      scales: {
        xAxes: [
          {
            display: true,
            scaleLabel: {
              display: true,
              labelString: 'Days Since Last Seen',
            },
          },
        ],
        yAxes: [
          {
            display: true,
            scaleLabel: {
              display: true,
              labelString: 'Devices',
            },
            ticks: {
              beginAtZero: true,
              stepSize: 1,
            },
          },
        ],
      },
    },
  });
}

  for (const platform in chartData.mdm_data) {
    const mdmData = chartData.mdm_data[platform];
    const crowdstrikeData = chartData.crowdstrike_data[platform];
    lineChartData.datasets.push({
      label: `${platform} - MDM`,
      data: mdmData,
      borderColor: getRandomColor(),
      fill: false,
    });
    lineChartData.datasets.push({
      label: `${platform} - Crowdstrike`,
      data: crowdstrikeData,
      borderColor: getRandomColor(),
      fill: false,
    });
  }

  const lineChartConfig = {
    type: 'line',
    data: lineChartData,
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Days Since Last Seen - MDM and Crowdstrike',
        },
      },
    },
  };

  const lineChart = new Chart(document.getElementById('line-chart'), lineChartConfig);

  // Pie charts for Not Found data
  const pieChartData = {
    labels: Object.keys(chartData.not_found_data),
    datasets: [
      {
        data: Object.values(chartData.not_found_data),
        backgroundColor: Object.keys(chartData.not_found_data).map(() => getRandomColor()),
      },
    ],
  };

  const pieChartConfig = {
    type: 'pie',
    data: pieChartData,
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Not Found Systems by Platform',
        },
      },
    },
  };

  const pieChart = new Chart(document.getElementById('pie-chart'), pieChartConfig);
}

function getRandomColor() {
  const letters = '0123456789ABCDEF';
  let color = '#';
  for (let i = 0; i < 6; i++) {
    color += letters[Math.floor(Math.random() * 16)];
  }
  return color;
}

// Fetch chart data from the server
fetch('/static/chart_data.json')
  .then((response) => response.json())
  .then((chartData) => {
    renderCharts(chartData);
  });

