<template>
  <div class="modal-overlay" @click.self="$emit('close')">
    <div class="scan-result-popup">
      <button class="close-btn" @click="$emit('close')">&times;</button>
      <h2>Scan Complete</h2>

      <div class="status-header">
        <img :src="statusIcon" alt="Status" class="status-icon" />
        <div class="status-text">
          <span v-if="scanDataComputed.isMalware" class="malware-detected">Malware Detected!</span>
          <span v-else class="no-malware">No Malware Detected</span>
          </div>
      </div>

      <div class="file-details">
        <div>
          <strong>File Name:</strong>
          <p>{{ scanDataComputed.fileName }}</p>
        </div>
        <div v-if="scanDataComputed.scanTime">
          <strong>Scan Time:</strong>
          <p>{{ scanDataComputed.scanTime }}</p>
        </div>
      </div>

      <div class="threat-info-simplified" v-if="scanDataComputed.isMalware">
        <h3>Threat Information</h3>
        <p><strong>Type:</strong> {{ scanDataComputed.malwareType }}</p>
        <p><strong>Confidence:</strong> {{ scanDataComputed.confidenceScore?.toFixed(2) }}%</p>
      </div>
      <div class="threat-info-simplified" v-else>
        <p>The file appears to be safe.</p>
      </div>


      <div class="actions">
        <button class="action-btn reanalyze-btn" @click="reanalyze">Reanalyze</button>
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
      required: true,
      default: () => ({ // Sensible defaults for a cleaner initial render
        fileName: 'N/A',
        isMalware: false,
        malwareType: 'N/A',
        confidenceScore: 0,
        scanTime: 'N/A'
      })
    }
  },
  computed: {
    // Use a computed property to handle potential undefined scanData on initial load
    scanDataComputed() {
      return this.scanData || this.$props.scanData.default();
    },
    statusIcon() {
      // Ensure you have these images in your public/assets folder or use other icons
      if (this.scanDataComputed.isMalware) {
        return '/img/malware_icon.png'; // Replace with your actual malware icon path
      }
      return '/img/safe_icon.png'; // Replace with your actual safe icon path
    }
    // riskClass can be removed if riskLevel is not a primary display item anymore
  },
  methods: {
    // severityClass can be removed if not used
    reanalyze() {
      this.$emit('reanalyze-request', this.scanDataComputed.fileName);
      this.$emit('close');
    }
  }
};
</script>

<style scoped>
/* Using your provided styles - no changes needed here unless you want to adjust for the simplified content */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5);
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
  max-width: 500px; /* Can make it a bit narrower for simpler content */
  position: relative;
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
  margin-bottom: 20px; /* Added more space */
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
    width: 40px; /* Adjusted size */
    height: 40px;
    margin-right: 15px;
    /* You'll need to provide actual image paths for statusIcon computed property */
}

.status-text .malware-detected {
    font-size: 1.25em; /* Slightly adjusted */
    font-weight: bold;
    color: #d9534f; 
    display: block;
}
.status-text .no-malware {
    font-size: 1.25em; /* Slightly adjusted */
    font-weight: bold;
    color: #5cb85c; 
    display: block;
}

/* Risk level display is removed from the template, so .risk-level and .high-risk can be removed if not used elsewhere */

.file-details {
  /* display: grid; */ /* Can simplify if fewer details */
  /* grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); */
  /* gap: 15px; */
  margin-bottom: 20px;
  font-size: 0.95em; /* Slightly larger base font */
}

.file-details div {
  margin-bottom: 8px; /* Space between file detail items */
}
.file-details strong {
    display: block;
    color: #555;
    margin-bottom: 4px; /* More space */
}
.file-details p {
  margin: 0;
  color: #333;
}

/* Removed .file-icon-placeholder as it's not in the simplified template */

.threat-info-simplified {
  margin-bottom: 25px;
  padding: 15px;
  background-color: #f9f9f9;
  border-radius: 6px;
}
.threat-info-simplified h3 {
    font-size: 1.1em;
    color: #444;
    margin-top: 0;
    margin-bottom: 10px;
}
.threat-info-simplified p {
  margin: 5px 0;
  font-size: 1em;
}


/* Table styles for threat-details-section can be removed if you're not using the table anymore */

.actions {
  display: flex;
  justify-content: flex-end; 
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

/* .details-btn and .download-btn can be removed if not used */
.reanalyze-btn {
  /* Add specific styles if needed */
}
</style>