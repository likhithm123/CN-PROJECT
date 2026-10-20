/**
 * Charts Module for Hybrid NIDS Real-Time SOC Dashboard.
 * Manages dynamic Chart.js instances for network throughput and threat distribution.
 */

let trafficLineChart = null;
let threatDistributionChart = null;

const maxHistoryPoints = 25;
const chartLabels = [];
const ppsData = [];
const kbpsData = [];

export function initCharts() {
  const lineCtx = document.getElementById("trafficLineChart")?.getContext("2d");
  const donutCtx = document.getElementById("threatDonutChart")?.getContext("2d");

  // Prepopulate history labels
  for (let i = maxHistoryPoints; i >= 0; i--) {
    chartLabels.push("");
    ppsData.push(0);
    kbpsData.push(0);
  }

  if (lineCtx) {
    trafficLineChart = new Chart(lineCtx, {
      type: "line",
      data: {
        labels: chartLabels,
        datasets: [
          {
            label: "Packets / sec (PPS)",
            data: ppsData,
            borderColor: "#00f2fe",
            backgroundColor: "rgba(0, 242, 254, 0.08)",
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            yAxisID: "y"
          },
          {
            label: "Bandwidth (KB/s)",
            data: kbpsData,
            borderColor: "#9d4edd",
            backgroundColor: "rgba(157, 78, 221, 0.05)",
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            yAxisID: "y1"
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: {
            labels: { color: "#94a3b8", font: { size: 11 } }
          }
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.03)" },
            ticks: { display: false }
          },
          y: {
            type: "linear",
            display: true,
            position: "left",
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#64748b", font: { size: 10 } }
          },
          y1: {
            type: "linear",
            display: true,
            position: "right",
            grid: { drawOnChartArea: false },
            ticks: { color: "#64748b", font: { size: 10 } }
          }
        }
      }
    });
  }

  if (donutCtx) {
    threatDistributionChart = new Chart(donutCtx, {
      type: "doughnut",
      data: {
        labels: ["Benign / Normal", "SYN Flood", "Port Scan", "ICMP/UDP Flood", "Zero-Day Anomaly"],
        datasets: [
          {
            data: [1, 0, 0, 0, 0],
            backgroundColor: [
              "#00f59b", // Green
              "#ff3366", // Red
              "#ff9900", // Orange
              "#4facfe", // Blue
              "#9d4edd"  // Purple
            ],
            borderWidth: 0
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "70%",
        plugins: {
          legend: {
            position: "right",
            labels: { color: "#94a3b8", boxWidth: 12, font: { size: 11 } }
          }
        }
      }
    });
  }
}

export function updateTrafficChart(pps, bps) {
  if (!trafficLineChart) return;
  const kbps = Math.round((bps / 8) / 1024);

  ppsData.shift();
  ppsData.push(pps);

  kbpsData.shift();
  kbpsData.push(kbps);

  trafficLineChart.update();
}

export function updateThreatDonut(distribution) {
  if (!threatDistributionChart) return;
  threatDistributionChart.data.datasets[0].data = [
    distribution.benign || 1,
    distribution.syn_flood || 0,
    distribution.port_scan || 0,
    distribution.flood || 0,
    distribution.zero_day || 0
  ];
  threatDistributionChart.update();
}
