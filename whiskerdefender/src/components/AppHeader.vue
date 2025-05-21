<template>
  <header class="app-header">
    <div class="logo-container">
      <img src="@/assets/cat-logo.png" alt="WhiskerDefender Logo" class="logo-img" />
      <h1 class="app-title">WhiskerDefender</h1>
    </div>
    <nav class="navigation">
      <button v-if="!isLoggedIn" @click="handleLogin" class="login-btn">Login</button>
      <span v-if="isLoggedIn" class="user-greeting">Hello, {{ username }}!</span>
      <button v-if="isLoggedIn" @click="handleLogout" class="logout-btn">Logout</button>
      <button class="menu-btn">&#9776;</button> </nav>
  </header>
</template>

<script>
export default {
  name: 'AppHeader',
  props: {
    isLoggedIn: Boolean,
    username: String,
  },
  methods: {
    handleLogin() {
      // In a real app, this would trigger a login modal or redirect to a login page.
      // For simulation, we'll emit an event.
      this.$emit('login-attempt');
    },
    handleLogout() {
      this.$emit('logout');
    }
  }
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
  box-shadow: 0 2px 4px rgba(0,0,0,0.05); /* Subtle shadow */
}

.logo-container {
  display: flex;
  align-items: center;
}

.logo-img {
  height: 45px; /* Slightly larger logo */
  margin-right: 12px;
  /* Make sure to add your cat logo to the src/assets folder */
}

.app-title {
  font-size: 1.9em; /* Slightly larger title */
  margin: 0;
  font-weight: 700; /* Bolder */
  color: #333;
}

.navigation {
  display: flex;
  align-items: center;
}

.navigation button {
  margin-left: 15px;
  padding: 9px 18px; /* Slightly larger buttons */
  border: none;
  cursor: pointer;
  border-radius: 5px;
  font-weight: 500;
  transition: background-color 0.2s, box-shadow 0.2s;
}

.login-btn {
  background-color: #007bff;
  color: white;
}
.login-btn:hover {
  background-color: #0056b3;
  box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

.logout-btn {
  background-color: #6c757d; /* Grey for logout */
  color: white;
}
.logout-btn:hover {
  background-color: #5a6268;
  box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}


.menu-btn {
  background-color: transparent;
  font-size: 1.6em; /* Larger menu icon */
  color: #555;
  padding: 5px 10px; /* Adjust padding for icon button */
}
.menu-btn:hover {
  background-color: #f0f0f0;
}

.user-greeting {
  margin-right: 15px;
  color: #555;
  font-weight: 500;
}
</style>
