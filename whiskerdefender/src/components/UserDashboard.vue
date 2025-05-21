<template>
  <div class="user-dashboard">
    <h2>Welcome to your Dashboard, {{ username }}!</h2>
    <p>This is your personal space to view scan history and manage your account.</p>

    <div class="dashboard-sections">
      <section class="scan-history">
        <h3>Recent Scans</h3>
        <div v-if="isLoadingHistory" class="loading-spinner">Loading scan history...</div>
        <div v-if="!isLoadingHistory && scanHistory.length === 0" class="no-data">
          You haven't performed any scans yet.
        </div>
        <ul v-if="!isLoadingHistory && scanHistory.length > 0">
          <li v-for="scan in scanHistory" :key="scan.id">
            <strong>{{ scan.fileName }}</strong> - 
            <span>{{ scan.isMalware ? 'Malware (' + scan.malwareType + ')' : 'Benign' }}</span>
            <span class="scan-date"> ({{ formatTimestamp(scan.scanTime) }})</span>
            <button @click="viewScanDetails(scan)" class="details-btn-small">Details</button>
          </li>
        </ul>
      </section>

      <section class="user-stats">
        <h3>Your Stats (Placeholder)</h3>
        <p>Files Scanned: 0</p>
        <p>Threats Found: 0</p>
      </section>

      <section class="account-settings">
        <h3>Account Settings (Placeholder)</h3>
        <button>Change Password</button>
        <button>Update Profile</button>
      </section>
    </div>

    <div v-if="selectedScanForDetails" class="modal-overlay" @click.self="selectedScanForDetails = null">
        <div class="detailed-report-popup">
            <button class="close-btn" @click="selectedScanForDetails = null">&times;</button>
            <h3>Detailed Scan Report</h3>
            <p><strong>File:</strong> {{ selectedScanForDetails.fileName }}</p>
            <p><strong>Status:</strong> {{ selectedScanForDetails.isMalware ? 'Malware' : 'Benign' }}</p>
            <p v-if="selectedScanForDetails.isMalware"><strong>Type:</strong> {{ selectedScanForDetails.malwareType }}</p>
            <p v-if="selectedScanForDetails.isMalware"><strong>Confidence:</strong> {{ selectedScanForDetails.confidenceScore?.toFixed(2) }}%</p>
            <p><strong>Scanned On:</strong> {{ formatTimestamp(selectedScanForDetails.scanTime) }}</p>
            <p><em>More detailed analysis results would appear here...</em></p>
        </div>
    </div>

  </div>
</template>

<script>
export default {
  name: 'UserDashboard',
  props: {
    username: String,
  },
  data() {
    return {
      scanHistory: [], // To be populated from backend
      isLoadingHistory: false, // Initially true when fetching
      selectedScanForDetails: null,
      // Dummy data for now
      // In a real app, fetch this from a user-specific API endpoint
    };
  },
  methods: {
    async fetchUserScanHistory() {
      this.isLoadingHistory = true;
      // Simulate API call for dummy data
      // Replace with actual fetch to a user-specific endpoint:
      // e.g., fetch(`/api/user/${this.username}/scan-history`)
      await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate delay
      
      // Dummy history data
      this.scanHistory = [
        { id: 'scan1', fileName: 'document.exe', isMalware: true, malwareType: 'Trojan', confidenceScore: 92.5, scanTime: new Date(Date.now() - 86400000 * 1).toISOString() },
        { id: 'scan2', fileName: 'installer.exe', isMalware: false, scanTime: new Date(Date.now() - 86400000 * 2).toISOString() },
        { id: 'scan3', fileName: 'archive.zip.exe', isMalware: true, malwareType: 'Ransomware', confidenceScore: 98.1, scanTime: new Date(Date.now() - 86400000 * 3).toISOString() },
      ].sort((a, b) => new Date(b.scanTime) - new Date(a.scanTime)); // Sort by date descending
      this.isLoadingHistory = false;
    },
    formatTimestamp(timestamp) {
      if (!timestamp) return 'N/A';
      try {
        return new Date(timestamp).toLocaleString('en-US', {
          year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
        });
      } catch (e) {
        return timestamp;
      }
    },
    viewScanDetails(scan) {
        this.selectedScanForDetails = scan;
        console.log("Viewing details for:", scan);
        // In a real app, you might fetch more details or show a more complex modal
    }
  },
  mounted() {
    this.fetchUserScanHistory();
  }
};
</script>

<style scoped>
.user-dashboard {
  padding: 25px 30px;
  max-width: 1100px;
  margin: 20px auto;
  background-color: #fff;
  border-radius: 10px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.08);
}

.user-dashboard h2 {
  text-align: center;
  color: #007bff; /* Theme color */
  margin-bottom: 30px;
  font-size: 2em;
}
.user-dashboard p {
    text-align: center;
    color: #555;
    margin-bottom: 30px;
    font-size: 1.1em;
}

.dashboard-sections {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 30px;
}

.dashboard-sections section {
  background-color: #f9f9f9;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 5px rgba(0,0,0,0.05);
}

.dashboard-sections h3 {
  margin-top: 0;
  color: #343a40;
  border-bottom: 2px solid #007bff;
  padding-bottom: 10px;
  margin-bottom: 15px;
}

.scan-history ul {
  list-style-type: none;
  padding: 0;
}
.scan-history li {
  padding: 10px 0;
  border-bottom: 1px solid #eee;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.scan-history li:last-child {
  border-bottom: none;
}
.scan-history .scan-date {
  font-size: 0.85em;
  color: #777;
  margin-left: 10px;
}
.details-btn-small {
    padding: 5px 10px;
    font-size: 0.8em;
    background-color: #007bff;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.details-btn-small:hover {
    background-color: #0056b3;
}


.loading-spinner, .no-data {
  text-align: center;
  padding: 15px;
  font-size: 1em;
  color: #6c757d;
}

.modal-overlay { /* For detailed report popup */
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.6);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1050; /* Higher than other elements */
}

.detailed-report-popup {
  background-color: #fff;
  padding: 25px;
  border-radius: 8px;
  box-shadow: 0 5px 15px rgba(0,0,0,0.3);
  width: 90%;
  max-width: 500px;
  position: relative;
}
.detailed-report-popup .close-btn {
  position: absolute;
  top: 10px;
  right: 15px;
  background: none;
  border: none;
  font-size: 1.8em;
  cursor: pointer;
  color: #aaa;
}
.detailed-report-popup h3 {
    margin-top: 0;
    color: #007bff;
}
</style>
