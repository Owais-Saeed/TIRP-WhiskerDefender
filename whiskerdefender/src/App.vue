<template>
  <div id="app">
    <AppHeader 
      :is-logged-in="auth.isLoggedIn" 
      :username="auth.username"
      @login-attempt="promptLogin"
      @logout="handleLogout"
    />

    <nav class="sub-nav" v-if="auth.isLoggedIn">
      <a href="#" @click.prevent="currentView = 'mainApp'">File Scan</a>
      <a href="#" @click.prevent="currentView = 'userDashboard'" v-if="auth.role === 'user' || auth.role === 'admin'">My Dashboard</a>
      <a href="#" @click.prevent="currentView = 'adminDashboard'" v-if="auth.role === 'admin'">Admin Dashboard</a>
    </nav>

    <main class="main-content" v-if="currentView === 'mainApp'">
      <div class="upload-section">
        <FileUpload @file-uploaded="handleFile" :key="fileUploadKey" /> </div>
      <div class="info-section">
        <MalwareDetectionInfo @run-scan="initiateScan" />
      </div>
    </main>

    <UserDashboard v-if="currentView === 'userDashboard' && auth.isLoggedIn" :username="auth.username" />

    <AdminDashboard v-if="currentView === 'adminDashboard' && auth.isLoggedIn && auth.role === 'admin'" />
    
    <div class="explore-section" v-if="currentView === 'mainApp'">
      <a href="#" @click.prevent="exploreMore">Explore more</a>
    </div>

    <ScanResultPopup 
      v-if="showScanResult && currentView === 'mainApp'" 
      :scan-data="scanResultData" 
      @close="showScanResult = false"
      @reanalyze-request="handleReanalyze" 
    />
  </div>
</template>

<script>
import AppHeader from './components/AppHeader.vue';
import FileUpload from './components/FileUpload.vue';
import MalwareDetectionInfo from './components/MalwareDetectionInfo.vue';
import ScanResultPopup from './components/ScanResultPopup.vue';
import AdminDashboard from './components/AdminDashboard.vue';
import UserDashboard from './components/UserDashboard.vue'; // Import UserDashboard

export default {
  name: 'App',
  components: {
    AppHeader,
    FileUpload,
    MalwareDetectionInfo,
    ScanResultPopup,
    AdminDashboard,
    UserDashboard, // Register UserDashboard
  },
  data() {
    return {
      uploadedFile: null,
      fileUploadKey: 0, // To force FileUpload re-render on clear
      showScanResult: false,
      scanResultData: null,
      currentView: 'mainApp', // 'mainApp', 'adminDashboard', 'userDashboard'
      auth: {
        isLoggedIn: false,
        username: '',
        role: '' // 'user' or 'admin'
      },
      // Store scan status for FileUpload component
      scanInProgress: false,
      scanStatusMessage: '',
    };
  },
  methods: {
    handleFile(file) {
      this.uploadedFile = file;
      if (file) {
        this.scanStatusMessage = `File selected: ${file.name}`;
        console.log('File selected:', file.name);
      } else {
        this.scanStatusMessage = '';
        console.log('File cleared.');
      }
    },
    async initiateScan() {
      if (!this.uploadedFile) {
        alert('Please upload a file first!');
        return;
      }
      console.log('Initiating scan for:', this.uploadedFile.name);
      this.scanInProgress = true;
      this.scanStatusMessage = `Scanning ${this.uploadedFile.name}...`;
      this.showScanResult = false; // Hide previous results

      const formData = new FormData();
      formData.append('file', this.uploadedFile);

      try {
        const response = await fetch('http://localhost:5000/scan', {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ message: `Scan failed with status: ${response.status}` }));
          throw new Error(errorData.message || `Scan failed with status: ${response.status}`);
        }
        
        const data = await response.json();
        // Assuming backend sends data directly as per previous discussions
        this.scanResultData = data;
        this.showScanResult = true;
        this.scanStatusMessage = `Scan complete for ${this.uploadedFile.name}.`;

      } catch (err) {
        console.error("Scan error:", err);
        alert(err.message || 'Scan failed! Check console for details.');
        this.scanResultData = null;
        this.scanStatusMessage = `Scan failed for ${this.uploadedFile?.name || 'file'}.`;
      } finally {
        this.scanInProgress = false;
        // Optionally clear the file after scan
        // this.uploadedFile = null; 
        // this.fileUploadKey++; // Force re-render FileUpload to clear its state
      }
    },
    handleReanalyze(filename) {
      console.log("Reanalyze requested for:", filename);
      // For reanalyze, we need the file object again.
      // If `this.uploadedFile` is still the one to reanalyze:
      if (this.uploadedFile && this.uploadedFile.name === filename) {
        this.initiateScan();
      } else {
        alert("To reanalyze, please select the file again.");
        // Optionally, you could store a list of recently scanned files to allow re-scan without re-upload
      }
    },
    exploreMore() {
      console.log('Explore more clicked');
    },
    promptLogin() {
      // Simulate login - in a real app, show a modal or redirect
      const username = prompt("Enter username (type 'admin' for admin role, anything else for user):");
      if (username) {
        this.auth.isLoggedIn = true;
        this.auth.username = username;
        if (username.toLowerCase() === 'admin') {
          this.auth.role = 'admin';
          this.currentView = 'adminDashboard'; // Go to admin dash on admin login
        } else {
          this.auth.role = 'user';
          this.currentView = 'userDashboard'; // Go to user dash on user login
        }
      }
    },
    handleLogout() {
      this.auth.isLoggedIn = false;
      this.auth.username = '';
      this.auth.role = '';
      this.currentView = 'mainApp'; // Go back to main app view on logout
      this.uploadedFile = null; // Clear uploaded file on logout
      this.fileUploadKey++; // Reset FileUpload component
      this.scanStatusMessage = '';
    }
  }
};
</script>

<style>
/* Your existing global styles */
body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; /* Modern font stack */
  margin: 0;
  background-color: #f4f7f6;
  color: #333;
  line-height: 1.6;
}

#app {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.sub-nav { /* Style for the new navigation bar */
  display: flex;
  justify-content: center;
  padding: 10px 0;
  background-color: #e9ecef;
  border-bottom: 1px solid #dee2e6;
  gap: 20px; /* Space between nav links */
}
.sub-nav a {
  color: #0056b3; /* Darker blue for better contrast */
  text-decoration: none;
  font-weight: 500;
  padding: 8px 15px;
  border-radius: 4px;
  transition: background-color 0.2s, color 0.2s;
}
.sub-nav a:hover, .sub-nav a.router-link-exact-active /* If using Vue Router */ {
  background-color: #007bff;
  color: white;
}


.main-content {
  display: flex;
  flex-grow: 1;
  padding: 20px 40px;
  gap: 40px;
  align-items: flex-start; /* Keep items aligned to top */
  max-width: 1200px; /* Consistent max-width */
  width: 100%; /* Ensure it takes up available space */
  margin: 20px auto; /* Add some top/bottom margin */
  box-sizing: border-box; /* Include padding and border in the element's total width and height */
}

.upload-section {
  flex: 1 1 400px; /* Flex grow, shrink, basis */
  min-width: 300px; /* Minimum width before wrapping */
}

.info-section {
  flex: 1 1 500px; /* Flex grow, shrink, basis */
}

.explore-section {
  text-align: right;
  padding: 20px 40px;
  background-color: #fff; /* Give it a background if it's a footer-like area */
  border-top: 1px solid #eee;
}

.explore-section a {
  color: #007bff;
  text-decoration: none;
  font-weight: 500;
}
.explore-section a:hover {
  text-decoration: underline;
}

/* Responsive adjustments */
@media (max-width: 900px) {
  .main-content {
    flex-direction: column;
    align-items: center; /* Center items when stacked */
    padding: 20px;
  }
  .upload-section, .info-section {
    flex-basis: auto; /* Allow them to take full width when stacked */
    width: 100%;
    max-width: 600px; /* Max width for content sections on smaller screens */
  }
}
</style>
