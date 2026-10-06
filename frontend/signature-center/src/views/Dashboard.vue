<template>
  <section>
    <h1>لوحة التحكم الرئيسية</h1>

    <div class="stats">
      <div class="card">
        <div>طلبات التوقيع</div>
        <strong>0</strong>
      </div>

      <div class="card">
        <div>الشهادات</div>
        <strong>0</strong>
      </div>

      <div class="card">
        <div>المخاطر</div>
        <strong>0</strong>
      </div>

      <div class="card">
        <div>حالة النظام</div>
        <strong>Ready</strong>
      </div>
    </div>
  </section>
</template>

<style scoped>
h1 {
  margin-top: 0;
  margin-bottom: 24px;
}

.stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
}

.card strong {
  display: block;
  margin-top: 12px;
  font-size: 30px;
}

@media (max-width: 1000px) {
  .stats {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>
