<template>
  <div class="file-upload-container">
    <h2>Upload file</h2>
    <div
      class="upload-area"
      @dragover.prevent="onDragOver"
      @dragleave.prevent="onDragLeave"
      @drop.prevent="onDrop"
      @click="triggerFileInput"
      :class="{ 'drag-over': isDragging }"
    >
      <input type="file" ref="fileInput" @change="onFileSelected" style="display: none;" />
      <div v-if="!selectedFile" class="upload-placeholder">
        <span class="upload-icon">🔄</span> <p>Click to upload</p>
        <p class="drag-drop-text">(or drag and drop)</p>
      </div>
      <div v-else class="file-preview">
        <p>Selected: {{ selectedFile.name }}</p>
        <button @click="clearFile" class="clear-btn">Clear</button>
      </div>
    </div>
    <div v-if="uploadStatus" class="upload-status">
        {{ uploadStatus }}
    </div>
  </div>
</template>

<script>
export default {
  name: 'FileUpload',
  data() {
    return {
      isDragging: false,
      selectedFile: null,
      uploadStatus: '' // e.g., "Upload complete"
    };
  },
  methods: {
    triggerFileInput() {
      this.$refs.fileInput.click();
    },
    onFileSelected(event) {
      const files = event.target.files;
      if (files.length > 0) {
        this.selectedFile = files[0];
        this.$emit('file-uploaded', this.selectedFile);
        this.uploadStatus = 'File selected: ' + this.selectedFile.name; // Or "Upload complete" as in design
      }
      // Reset the input so the change event fires again for the same file
      this.$refs.fileInput.value = null;
    },
    onDragOver(event) {
      event.preventDefault();
      this.isDragging = true;
    },
    onDragLeave(event) {
      event.preventDefault();
      this.isDragging = false;
    },
    onDrop(event) {
      event.preventDefault();
      this.isDragging = false;
      const files = event.dataTransfer.files;
      if (files.length > 0) {
        this.selectedFile = files[0];
        this.$emit('file-uploaded', this.selectedFile);
        this.uploadStatus = 'File selected: ' + this.selectedFile.name;
      }
    },
    clearFile() {
      this.selectedFile = null;
      this.uploadStatus = '';
      this.$emit('file-uploaded', null); // Notify parent that file is cleared
    }
  }
};
</script>

<style scoped>
.file-upload-container {
  background-color: #fff;
  padding: 25px;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
  text-align: center;
}

.file-upload-container h2 {
  text-align: left;
  margin-top: 0;
  margin-bottom: 15px;
  font-size: 1.2em;
  color: #555;
}

.upload-area {
  border: 2px dashed #ccc;
  border-radius: 8px;
  padding: 40px 20px;
  cursor: pointer;
  transition: background-color 0.2s, border-color 0.2s;
  min-height: 150px; /* Adjust as needed */
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}

.upload-area.drag-over {
  background-color: #e9f5ff;
  border-color: #007bff;
}

.upload-placeholder .upload-icon {
  font-size: 2.5em;
  color: #007bff;
  margin-bottom: 10px;
}

.upload-placeholder p {
  margin: 5px 0;
  color: #777;
}
.drag-drop-text {
    font-size: 0.9em;
    color: #aaa;
}

.file-preview p {
  margin-bottom: 10px;
}

.clear-btn {
  background-color: #ff4d4f;
  color: white;
  border: none;
  padding: 8px 12px;
  border-radius: 4px;
  cursor: pointer;
}
.upload-status {
    margin-top: 10px;
    color: green; /* Or a more neutral color */
    font-weight: bold;
}
</style>