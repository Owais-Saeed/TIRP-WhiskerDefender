<template>
  <div class="modal-overlay" @click.self="$emit('close')">
    <div class="scan-result-popup">
      <button class="close-btn" @click="$emit('close')">&times;</button>
      <h2>Scan Complete</h2>

      <div class="status-header">
        <span class="status-emoji-icon">{{ statusIconEmoji }}</span>
        <div class="status-text">
          <span v-if="scanDataComputed.isMalware" class="malware-detected">Malware Detected!</span>
          <span v-else class="no-malware">No Malware Detected</span>
          <span v-if="scanDataComputed.riskLevel" class="risk-level" :class="riskClass">{{ scanDataComputed.riskLevel }}</span>
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
         <p v-if="typeof scanDataComputed.confidenceScore === 'number'"><strong>Confidence:</strong> {{ scanDataComputed.confidenceScore?.toFixed(2) }}%</p>
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
      default: () => ({
        fileName: 'N/A',
        isMalware: false,
        malwareType: 'N/A',
        confidenceScore: 0,
        scanTime: 'N/A',
        riskLevel: 'N/A' // Added default for riskLevel
      })
    }
  },
  computed: {
    scanDataComputed() {
      // Ensure scanData is an object, provide defaults if top-level keys are missing
      const defaults = {
        fileName: 'N/A',
        isMalware: false,
        malwareType: 'N/A',
        confidenceScore: 0,
        scanTime: 'N/A',
        riskLevel: 'Undetermined', // Default risk level
        ...this.scanData // Spread incoming scanData over defaults
      };
      return defaults;
    },
    statusIconEmoji() {
      if (this.scanDataComputed && this.scanDataComputed.isMalware !== undefined) {
        return this.scanDataComputed.isMalware ? '⚠️' : '✔️'; // Warning for malware, Check for safe
        // Alternatives: '❌' for malware, '✅' for safe
      }
      return '❓'; // Default for unknown status
    },
    riskClass() { // Kept if you still want to style the risk level text
      if (!this.scanDataComputed.riskLevel || this.scanDataComputed.riskLevel === 'N/A') return 'risk-unknown';
      return `risk-${this.scanDataComputed.riskLevel.toLowerCase().replace(/\s+/g, '-')}`;
    }
  },
  methods: {
    reanalyze() {
      this.$emit('reanalyze-request', this.scanDataComputed.fileName);
      this.$emit('close');
    },
    // severityClass can be removed if not used
    // severityClass(severity) {
    //   if (!severity) return '';
    //   return `severity-${severity.toLowerCase()}`;
    // }
  }
};
</script>

<style scoped>
/* Using your provided styles - minor adjustments for emoji icon */
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
  max-width: 500px;
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
  margin-bottom: 20px;
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

.status-emoji-icon { /* Style for the emoji */
    font-size: 2.5em; /* Adjust size as needed */
    margin-right: 15px;
    line-height: 1; /* Ensures proper vertical alignment */
}

.status-text .malware-detected {
    font-size: 1.25em;
    font-weight: bold;
    color: #d9534f; 
    display: block;
}
.status-text .no-malware {
    font-size: 1.25em;
    font-weight: bold;
    color: #5cb85c; 
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
.risk-critical { background-color: #7c0a02; }
.risk-high { background-color: #d9534f; }
.risk-medium { background-color: #f0ad4e; }
.risk-low { background-color: #5bc0de; }
.risk-unknown { background-color: #aaa; }


.file-details {
  margin-bottom: 20px;
  font-size: 0.95em;
}

.file-details div {
  margin-bottom: 8px;
}
.file-details strong {
    display: block;
    color: #555;
    margin-bottom: 4px;
}
.file-details p {
  margin: 0;
  color: #333;
}

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
</style>
