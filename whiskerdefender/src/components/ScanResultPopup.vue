<template>
  <div class="modal-overlay" @click.self="$emit('close')"> <div class="scan-result-popup">
      <button class="close-btn" @click="$emit('close')">&times;</button>
      <h2>Scan Complete</h2>

      <div class="status-header">
        <img src="" alt="Alert" class="status-icon" v-if="scanData.malwareDetected" />
        <div class="status-text">
            <span v-if="scanData.malwareDetected" class="malware-detected">Malware Detected!</span>
            <span v-else class="no-malware">No Malware Detected</span>
            <span v-if="scanData.riskLevel" class="risk-level" :class="riskClass">{{ scanData.riskLevel }}</span>
        </div>
      </div>

      <div class="file-details">
        <div>
          <strong>File Name:</strong>
          <p>{{ scanData.fileName }}</p>
        </div>
        <div>
          <strong>Scan Time:</strong>
          <p>{{ scanData.scanTime }}</p>
        </div>
        <div>
          <strong>File Image:</strong>
          <div class="file-icon-placeholder">{{ scanData.fileImage }}</div> </div>
      </div>

      <div class="threat-details-section" v-if="scanData.malwareDetected && scanData.threatDetails">
        <h3>Threat Details</h3>
        <table>
          <thead>
            <tr>
              <th>Signature</th>
              <th>Behavior</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>{{ scanData.threatDetails.signature }}</td>
              <td>{{ scanData.threatDetails.behavior }}</td>
              <td :class="severityClass(scanData.threatDetails.severity)">{{ scanData.threatDetails.severity }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="actions">
        <button class="action-btn reanalyze-btn">Reanalyze</button>
        <button class="action-btn details-btn">More Details</button>
        <button class="action-btn download-btn">Download</button>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'ScanResultPopup',
  props: {
    scanData: {
      type: Object,
      required: true
    }
  },
  computed: {
    riskClass() {
      if (!this.scanData.riskLevel) return '';
      return this.scanData.riskLevel.toLowerCase().replace(' ', '-'); // e.g., 'high-risk'
    }
  },
  methods: {
      severityClass(severity) {
          if (!severity) return '';
          return `severity-${severity.toLowerCase()}`;
      }
  }
  // Add methods for reanalyze, more details, download
};
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5); /* Semi-transparent background */
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.scan-result-popup {
  background-color: #fff;
  padding: 25px;
  border-radius: 8px;
  box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
  width: 90%;
  max-width: 600px; /* Adjust as per design */
  position: relative; /* For close button positioning */
}

.close-btn {
  position: absolute;
  top: 10px;
  right: 15px;
  background: none;
  border: none;
  font-size: 1.8em;
  cursor: pointer;
  color: #aaa;
}
.close-btn:hover {
    color: #333;
}

.scan-result-popup h2 {
  margin-top: 0;
  margin-bottom: 15px;
  font-size: 1.5em;
  color: #333;
  text-align: center;
}

.status-header {
    display: flex;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 1px solid #eee;
}

.status-icon {
    width: 50px; /* Adjust as needed */
    height: 50px;
    margin-right: 15px;
    /* Add your red-eyed cat image to src/assets, e.g., cat-alert-logo.png */
}

.status-text .malware-detected {
    font-size: 1.2em;
    font-weight: bold;
    color: #d9534f; /* Red color */
    display: block;
}
.status-text .no-malware {
    font-size: 1.2em;
    font-weight: bold;
    color: #5cb85c; /* Green color */
    display: block;
}

.risk-level {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.9em;
    font-weight: bold;
    color: white;
    margin-top: 5px;
}
.high-risk {
    background-color: #d9534f; /* Red for high risk */
}
/* Add other risk level classes as needed (e.g., medium-risk, low-risk) */


.file-details {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 15px;
  margin-bottom: 20px;
}

.file-details div {
  font-size: 0.9em;
}
.file-details strong {
    display: block;
    color: #555;
    margin-bottom: 3px;
}
.file-details p {
  margin: 0;
  color: #333;
}

.file-icon-placeholder {
  width: 50px;
  height: 60px;
  background-color: #eee; /* Placeholder, replace with actual PDF icon/image */
  display: flex;
  justify-content: center;
  align-items: center;
  border-radius: 4px;
  font-weight: bold;
  color: #777;
}

.threat-details-section {
  margin-bottom: 25px;
}
.threat-details-section h3 {
    font-size: 1.1em;
    color: #444;
    margin-bottom: 10px;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9em;
}

th, td {
  border: 1px solid #ddd;
  padding: 8px;
  text-align: left;
}

th {
  background-color: #f9f9f9;
  font-weight: bold;
  color: #555;
}
.severity-high {
    color: #d9534f; /* Red */
    font-weight: bold;
}
.severity-medium {
    color: #f0ad4e; /* Orange */
    font-weight: bold;
}
.severity-low {
    color: #5bc0de; /* Blue/Info */
    font-weight: bold;
}


.actions {
  display: flex;
  justify-content: flex-end; /* Align buttons to the right as in design */
  gap: 10px;
  margin-top: 20px;
}

.action-btn {
  padding: 10px 18px;
  border: 1px solid #ccc;
  border-radius: 5px;
  cursor: pointer;
  font-weight: 500;
  background-color: #f7f7f7;
  transition: background-color 0.2s;
}
.action-btn:hover {
    background-color: #e9e9e9;
}

.reanalyze-btn {
  /* Add specific styles if needed */
}

.details-btn {
  /* Add specific styles if needed */
}

.download-btn {
  background-color: #007bff; /* Blue for primary action */
  color: white;
  border-color: #007bff;
}
.download-btn:hover {
  background-color: #0056b3;
}
</style>