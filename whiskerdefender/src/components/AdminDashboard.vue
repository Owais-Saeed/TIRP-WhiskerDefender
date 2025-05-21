<template>
  <div class="admin-dashboard">
    <h2>Admin Dashboard</h2>
    
    <section class="dashboard-section">
      <h3>Top Malware Detections (Last 7 Days)</h3>
      <div v-if="isLoading.topScans" class="loading-spinner">Loading top scans...</div>
      <div v-if="errors.topScans" class="error-message">{{ errors.topScans }}</div>
      <div v-if="!isLoading.topScans && !errors.topScans && topScans.length === 0" class="no-data">
        No malware detections found in the last 7 days.
      </div>
      <table v-if="!isLoading.topScans && !errors.topScans && topScans.length > 0" class="scan-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Scan Date (UTC)</th>
            <th>File Name</th>
            <th>Detected Type</th>
            <th>Confidence</th>
            <th>Risk Level</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(scan, index) in topScans" :key="scan.id || index" :class="getRiskRowClass(scan.riskLevel)">
            <td>{{ index + 1 }}</td>
            <td>{{ formatScanTimestamp(scan.timestamp) }}</td>
            <td class="filename-cell">{{ scan.filename }}</td>
            <td>{{ scan.malwareType }}</td>
            <td>{{ scan.confidenceScore?.toFixed(2) }}%</td>
            <td><span class="risk-badge" :class="getRiskBadgeClass(scan.riskLevel)">{{ scan.riskLevel }}</span></td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="dashboard-section">
      <h3>Malware Statistics (Placeholders)</h3>
      <div class="charts-container">
        <div class="chart-placeholder">
          <h4>Malware Types Distribution (Last 7 Days)</h4>
          <div class="chart-area">
            <p><em>[Pie Chart Placeholder: e.g., Trojan: 40%, Ransomware: 30%, Spyware: 20%, Unknown: 10%]</em></p>
            <ul class="dummy-chart-legend">
              <li><span class="legend-color trojan"></span> Trojan (4)</li>
              <li><span class="legend-color ransomware"></span> Ransomware (3)</li>
              <li><span class="legend-color spyware"></span> Spyware (2)</li>
              <li><span class="legend-color unknown"></span> Unknown/Anomaly (1)</li>
            </ul>
          </div>
        </div>
        <div class="chart-placeholder">
          <h4>Scan Volume Over Time (Last 7 Days)</h4>
          <div class="chart-area">
            <p><em>[Line Chart Placeholder: Showing daily scan counts]</em></p>
            <p>Mon: 15, Tue: 22, Wed: 18, Thu: 25, Fri: 30, Sat: 12, Sun: 8</p>
          </div>
        </div>
      </div>
    </section>

    <section class="dashboard-section">
      <h3>User Activity Overview (Placeholders)</h3>
      <div class="user-activity-container">
        <div class="activity-placeholder">
          <h4>Top Scanning Users (Last 7 Days)</h4>
          <ul>
            <li>UserA (admin) - 15 scans</li>
            <li>UserB (user) - 10 scans</li>
            <li>UserC (user) - 8 scans</li>
          </ul>
        </div>
        <div class="activity-placeholder">
          <h4>Overall Scan Counts</h4>
          <p>Total Scans Today: 25</p>
          <p>Total Scans This Week: 120</p>
          <p>Total Malware Detections This Week: 35</p>
        </div>
      </div>
    </section>

  </div>
</template>

<script>
export default {
  name: 'AdminDashboard',
  data() {
    return {
      topScans: [],
      isLoading: { // Changed to an object for multiple loading states
        topScans: true,
        charts: true, // Placeholder
        userActivity: true, // Placeholder
      },
      errors: { // Changed to an object for multiple error states
        topScans: null,
        charts: null,
        userActivity: null,
      }
      // Dummy data for charts and user activity can be added here if needed for dynamic placeholders
      // e.g., chartData: { malwareTypes: [...], scanVolume: [...] }
      // e.g., userActivityData: { topUsers: [...], overallCounts: {...} }
    };
  },
  methods: {
    async fetchTopScans() {
      this.isLoading.topScans = true;
      this.errors.topScans = null;
      try {
        const response = await fetch('http://localhost:5000/api/admin/top-scans');
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ detail: 'Server error fetching top scans' }));
          throw new Error(errorData.detail || `HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();
        this.topScans = data;
      } catch (err) {
        console.error('Error fetching top scans:', err);
        this.errors.topScans = err.message || 'Failed to load top scans. Please try again.';
      } finally {
        this.isLoading.topScans = false;
      }
    },
    // Placeholder methods for fetching chart and user activity data
    async fetchChartData() {
      this.isLoading.charts = true;
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));
      // Populate with dummy chart data if needed, or just set loading to false
      this.isLoading.charts = false;
      console.log("Placeholder: Chart data would be fetched here.");
    },
    async fetchUserActivity() {
      this.isLoading.userActivity = true;
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));
      // Populate with dummy user activity data if needed, or just set loading to false
      this.isLoading.userActivity = false;
      console.log("Placeholder: User activity data would be fetched here.");
    },
    formatScanTimestamp(timestamp) {
      if (!timestamp) return 'N/A';
      try {
        const date = new Date(timestamp.replace(' UTC', 'Z')); 
         return date.toLocaleString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true 
        });
      } catch (e) {
        return timestamp; 
      }
    },
    getRiskRowClass(riskLevel) {
      if (!riskLevel) return 'risk-row-unknown';
      const risk = riskLevel.toLowerCase();
      if (risk === 'critical') return 'risk-row-critical';
      if (risk === 'high') return 'risk-row-high';
      return ''; 
    },
    getRiskBadgeClass(riskLevel) {
       if (!riskLevel) return 'risk-badge-unknown';
      return `risk-badge-${riskLevel.toLowerCase().replace(/\s+/g, '-')}`;
    }
  },
  mounted() {
    this.fetchTopScans();
    this.fetchChartData(); // Call placeholder fetch methods
    this.fetchUserActivity(); // Call placeholder fetch methods
  },
};
</script>

<style scoped>
.admin-dashboard {
  padding: 25px 30px; 
  max-width: 1100px; 
  margin: 30px auto; 
  background-color: #ffffff; 
  border-radius: 10px; 
  box-shadow: 0 4px 12px rgba(0,0,0,0.08); 
  border-top: 4px solid #007bff; 
}

.admin-dashboard h2 { /* Overall Dashboard Title */
  text-align: center;
  color: #343a40; 
  margin-bottom: 30px; 
  font-size: 1.8em;
}

.dashboard-section {
  background-color: #fff;
  padding: 20px;
  margin-bottom: 30px;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.07);
}

.dashboard-section h3 { /* Section Titles */
  font-size: 1.4em;
  color: #007bff; /* Theme color for section titles */
  margin-top: 0;
  margin-bottom: 20px;
  padding-bottom: 10px;
  border-bottom: 2px solid #e9ecef; /* Light separator */
}


.loading-spinner, .error-message, .no-data {
  text-align: center;
  padding: 25px;
  font-size: 1.1em;
  border-radius: 6px; 
}

.error-message {
  color: #721c24; 
  background-color: #f8d7da; 
  border: 1px solid #f5c6cb;
}

.no-data {
  color: #6c757d; 
  background-color: #e9ecef; 
  border: 1px solid #dee2e6;
}

/* Table Styles (from previous version, largely unchanged) */
.scan-table {
  width: 100%;
  border-collapse: separate; 
  border-spacing: 0; 
  margin-top: 0; /* Adjusted as it's inside a section */
  box-shadow: none; /* Removed as section has shadow */
  border-radius: 8px; 
  overflow: hidden; 
}

.scan-table th, .scan-table td {
  padding: 12px 15px; 
  text-align: left;
  font-size: 0.9em; 
  border-bottom: 1px solid #dee2e6; 
}

.scan-table th {
  background-color: #f8f9fa; 
  color: #495057; 
  font-weight: 600; 
  text-transform: uppercase;
  font-size: 0.85em;
  letter-spacing: 0.05em;
  border-top: 1px solid #dee2e6; 
}
.scan-table th:first-child { border-top-left-radius: 8px; }
.scan-table th:last-child { border-top-right-radius: 8px; }
.scan-table tbody tr { background-color: #fff; transition: background-color 0.15s ease-in-out; }
.scan-table tbody tr:nth-child(even) { background-color: #f9f9f9; }
.scan-table tbody tr:hover { background-color: #eef8ff; }
.scan-table tbody tr:last-child td { border-bottom: none; }
.scan-table tbody tr:last-child td:first-child { border-bottom-left-radius: 8px; }
.scan-table tbody tr:last-child td:last-child { border-bottom-right-radius: 8px; }
.risk-row-critical { background-color: #ffebee !important; }
.risk-row-critical:hover { background-color: #ffcdd2 !important; }
.risk-row-high { background-color: #fff3e0 !important; }
.risk-row-high:hover { background-color: #ffe0b2 !important; }
.risk-badge { padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; color: #fff; text-transform: uppercase; white-space: nowrap; }
.risk-badge-critical { background-color: #c62828; } 
.risk-badge-high { background-color: #d9534f; } 
.risk-badge-medium { background-color: #f0ad4e; } 
.risk-badge-low { background-color: #5bc0de; } 
.risk-badge-unknown { background-color: #adb5bd; } 
.filename-cell { word-break: break-all; max-width: 250px; }

/* Styles for new placeholder sections */
.charts-container, .user-activity-container {
  display: flex;
  flex-wrap: wrap; /* Allow wrapping on smaller screens */
  gap: 20px; /* Space between chart/activity blocks */
}

.chart-placeholder, .activity-placeholder {
  flex: 1; /* Each takes equal space */
  min-width: 300px; /* Minimum width before wrapping */
  background-color: #f8f9fa; /* Light background for placeholders */
  padding: 20px;
  border-radius: 6px;
  border: 1px dashed #ced4da; /* Dashed border to indicate placeholder */
}

.chart-placeholder h4, .activity-placeholder h4 {
  margin-top: 0;
  margin-bottom: 15px;
  font-size: 1.1em;
  color: #495057;
}

.chart-area {
  min-height: 150px; /* Give some space for the chart idea */
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  color: #6c757d;
}
.chart-area p {
    margin: 5px 0;
}

.dummy-chart-legend {
    list-style: none;
    padding: 0;
    margin-top: 10px;
    font-size: 0.9em;
}
.dummy-chart-legend li {
    margin-bottom: 5px;
    display: flex;
    align-items: center;
}
.legend-color {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    margin-right: 8px;
}
.legend-color.trojan { background-color: #dc3545; } /* Example color */
.legend-color.ransomware { background-color: #fd7e14; } /* Example color */
.legend-color.spyware { background-color: #ffc107; } /* Example color */
.legend-color.unknown { background-color: #6c757d; } /* Example color */


.activity-placeholder ul {
  list-style-type: none;
  padding: 0;
}
.activity-placeholder li, .activity-placeholder p {
  margin-bottom: 8px;
  font-size: 0.95em;
  color: #495057;
}
</style>