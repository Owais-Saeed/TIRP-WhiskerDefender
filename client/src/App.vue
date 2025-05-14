<template>
  <div class="container">
    <ScanForm @scanComplete="handleScanResult" />
    <ScanResult v-if="result" :result="result" @close="result = null" />
  </div>
</template>

<script>
import ScanForm from './components/ScanForm.vue'
import ScanResult from './components/ScanResult.vue'

export default {
  components: { ScanForm, ScanResult },
  data() {
    return {
      result: null
    }
  },
  methods: {
    handleScanResult(resultData) {
      this.result = resultData
    }
  }
}
</script>
