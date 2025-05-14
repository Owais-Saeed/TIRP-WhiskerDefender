<template>
  <header class="app-header">
    <div class="logo-container">
      <img src="@/assets/cat-logo.png" alt="WhiskerDefender Logo" class="logo-img" />
      <h1 class="app-title">WhiskerDefender</h1>
    </div>
    <nav class="navigation">
      <button class="login-btn">Login</button>
      <button class="menu-btn">&#9776;</button> </nav>
  </header>
</template>

<script>
export default {
  name: 'AppHeader'
  // Add methods for login and menu toggle if needed
};
</script>

<style scoped>
.app-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px 30px;
  background-color: #fff; /* White background for header */
  border-bottom: 1px solid #eee;
}

.logo-container {
  display: flex;
  align-items: center;
}

.logo-img {
  height: 40px; /* Adjust as needed */
  margin-right: 10px;
  /* Make sure to add your cat logo to the src/assets folder */
}

.app-title {
  font-size: 1.8em;
  margin: 0;
  font-weight: bold; /* Making it bold as per design */
}

.navigation button {
  margin-left: 15px;
  padding: 8px 15px;
  border: none;
  cursor: pointer;
  border-radius: 5px;
}

.login-btn {
  background-color: #007bff; /* Blue color from your design */
  color: white;
}

.menu-btn {
  background-color: transparent;
  font-size: 1.5em;
  color: #333;
}
</style>