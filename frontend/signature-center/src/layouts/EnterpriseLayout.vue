<template>
  <div class="app-shell">

    <aside class="sidebar">

      <div class="brand">
        <div class="brand-title">
          Surhan Signature
        </div>

        <div class="brand-subtitle">
          Enterprise Signing Center
        </div>
      </div>

      <nav class="navigation">

        <RouterLink to="/dashboard" class="nav-item">
          لوحة التحكم
        </RouterLink>

        <RouterLink to="/envelopes" class="nav-item">
          طلبات التوقيع
        </RouterLink>

        <RouterLink to="/certificates" class="nav-item">
          الشهادات الرقمية
        </RouterLink>

        <RouterLink to="/audit" class="nav-item">
          سجل التدقيق
        </RouterLink>

        <RouterLink to="/security" class="nav-item">
          مركز الأمان
        </RouterLink>

      </nav>

    </aside>

    <main class="main-content">
      <RouterView />
    </main>

  </div>
</template>

<style scoped>
.app-shell {
  min-height: 100vh;
  display: flex;
  direction: rtl;
}

.sidebar {
  width: 280px;
  min-height: 100vh;
  background: #0f172a;
  color: white;
  padding: 24px;
  flex-shrink: 0;
}

.brand {
  margin-bottom: 40px;
}

.brand-title {
  font-size: 24px;
  font-weight: 700;
}

.brand-subtitle {
  margin-top: 6px;
  font-size: 13px;
  color: #94a3b8;
}

.navigation {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.nav-item {
  padding: 13px 16px;
  border-radius: 10px;
  color: #cbd5e1;
  transition: 0.2s;
}

.nav-item:hover,
.nav-item.router-link-active {
  background: #1e293b;
  color: white;
}

.main-content {
  flex: 1;
  min-width: 0;
  padding: 32px;
  background: #f5f7fb;
}
</style>
