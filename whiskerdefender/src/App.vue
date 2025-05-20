<template>
  <div id="app">
    <AppHeader />
    <main class="main-content">
      <div class="upload-section">
        <FileUpload @file-uploaded="handleFile" />
      </div>
      <div class="info-section">
        <MalwareDetectionInfo @run-scan="initiateScan" />
      </div>
    </main>
    <div class="explore-section">
      <a href="#" @click.prevent="exploreMore">Explore more</a>
    </div>
    <ScanResultPopup v-if="showScanResult" :scan-data="scanResultData" @close="showScanResult = false" />
  </div>
</template>

<script>
import AppHeader from './components/AppHeader.vue';
import FileUpload from './components/FileUpload.vue';
import MalwareDetectionInfo from './components/MalwareDetectionInfo.vue';
import ScanResultPopup from './components/ScanResultPopup.vue';

export default {
  name: 'App',
  components: {
    AppHeader,
    FileUpload,
    MalwareDetectionInfo,
    ScanResultPopup
  },
  data() {
    return {
      uploadedFile: null,
      showScanResult: false,
      scanResultData: null // This will be populated by your backend/ML model
    };
  },
  methods: {
    handleFile(file) {
      this.uploadedFile = file;
      console.log('File selected:', file.name);
      // You might want to immediately show some feedback or enable the "Run Pawtection" button
    },
    initiateScan() 
    {
      if (!this.uploadedFile) {
        alert('Please upload a file first!');
        return;
      }
      console.log('Initiating scan for:', this.uploadedFile.name);

      // // For now, let's simulate a response:
      // setTimeout(() => { // Simulate network delay
      //   this.scanResultData = {
      //     fileName: this.uploadedFile.name,
      //     scanTime: '4.3s', // Or calculate actual time
      //     fileImage: 'PDF', // Determine based on file type
      //     malwareDetected: true,
      //     riskLevel: 'High Risk',
      //     threatDetails: {
      //       signature: 'Trojan.Gen.ML',
      //       behavior: 'Keylogging & Encryption Activity',
      //       severity: 'High'
      //     }
      //   };
      //   this.showScanResult = true;
      // }, 2000);

      const formData = new FormData();
      formData.append('file', this.uploadedFile);

      fetch('http://localhost:5000/scan', {  // adjust if using a proxy
        method: 'POST',
        body: formData
      })
        .then(res => res.json())
        .then(data => {
          this.scanResultData = data;
          this.showScanResult = true;
        })
        .catch(err => {
          console.error("Scan error:", err);
          alert('Scan failed!');
        });
    },
    exploreMore() {
      console.log('Explore more clicked');
      // Implement navigation or show more content
    }
  }
};
</script>

<style>
/* Add global styles or import a CSS framework like Tailwind CSS, BootstrapVue, etc. */
body {
  font-family: sans-serif;
  margin: 0;
  background-color: #f4f7f6; /* Light greyish background from image */
  color: #333;
}

#app {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.main-content {
  display: flex;
  flex-grow: 1;
  padding: 40px;
  gap: 40px; /* Space between upload and info sections */
  align-items: flex-start; /* Align items to the top */
  max-width: 1200px;
  margin: 0 auto;
}

.upload-section {
  flex-basis: 40%; /* Adjust as needed */
}

.info-section {
  flex-basis: 60%; /* Adjust as needed */
}

.explore-section {
  text-align: right;
  padding: 20px 40px;
}

.explore-section a {
  color: #007bff; /* Or your theme color */
  text-decoration: none;
}
</style>