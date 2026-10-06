import {
  createRouter,
  createWebHistory,
} from "vue-router"

import Dashboard from "../views/Dashboard.vue"
import Envelopes from "../views/Envelopes.vue"
import Certificates from "../views/Certificates.vue"
import Security from "../views/Security.vue"
import Audit from "../views/Audit.vue"

const routes = [
  {
    path: "/",
    redirect: "/dashboard",
  },
  {
    path: "/dashboard",
    component: Dashboard,
  },
  {
    path: "/envelopes",
    component: Envelopes,
  },
  {
    path: "/certificates",
    component: Certificates,
  },
  {
    path: "/security",
    component: Security,
  },
  {
    path: "/audit",
    component: Audit,
  },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
