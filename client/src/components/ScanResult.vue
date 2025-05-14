<template>
  <div class="scan-result">
    <h3>Scan Complete</h3>
    <p><strong>Status:</strong> Threat Detected</p>
    <p><strong>Risk Level:</strong> {{ result.threatLevel }}</p>
    <p><strong>Signature Match:</strong> {{ result.signature }}</p>
    <p><strong>Behavior:</strong> {{ result.behavior }}</p>
    <p><strong>File:</strong> {{ result.fileName }}</p>
    <p><strong>Scan Time:</strong> {{ result.scanTime }}</p>

    <h4>Security Recommendations</h4>
    <ul>
      <li>Do not open this file.</li>
      <li>Quarantine the file immediately.</li>
      <li>Perform a full system scan.</li>
    </ul>

    <div class="buttons">
      <button @click="$emit('close')">Close</button>
      <button>View Full Report</button>
      <button>Download Report</button>
    </div>
  </div>
</template>

<script>
export default {
  props: ['result']
}
</script>
