#!/bin/bash

set -e

APP_PATH="/home/frappe/frappe-bench/apps/surhan_signature"
FRONTEND_PATH="$APP_PATH/frontend/signature-center"
SITE="ysmo"

echo "======================================"
echo " Surhan Signature Vue 3 Installer"
echo " Frappe Enterprise Integration"
echo "======================================"

cd $APP_PATH


echo "[1/10] Checking environment..."

NODE_VERSION=$(node -v)
NPM_VERSION=$(npm -v)

echo "Node: $NODE_VERSION"
echo "NPM : $NPM_VERSION"


if ! command -v node >/dev/null 2>&1
then
    echo "Node.js not found"
    exit 1
fi


if ! command -v npm >/dev/null 2>&1
then
    echo "npm not found"
    exit 1
fi



echo "[2/10] Creating Vue application structure..."


mkdir -p $FRONTEND_PATH


cd $APP_PATH/frontend


if [ ! -f "$FRONTEND_PATH/package.json" ]
then

npm create vite@latest signature-center \
-- --template vue-ts

fi


cd $FRONTEND_PATH


echo "[3/10] Installing packages..."


npm install


npm install \
vue-router \
pinia \
axios \
vue-i18n \
echarts \
vue-echarts \
pdfjs-dist \
vuedraggable@next


npm install -D \
tailwindcss \
postcss \
autoprefixer



echo "[4/10] Initializing Tailwind..."

npx tailwindcss init -p



echo "[5/10] Creating source folders..."

mkdir -p src/api
mkdir -p src/router
mkdir -p src/stores
mkdir -p src/layouts
mkdir -p src/components
mkdir -p src/views


echo "Frontend base created successfully"

echo "[6/10] Configuring Tailwind RTL..."

cat > tailwind.config.js <<'EOF'
/** @type {import('tailwindcss').Config} */

export default {

content:[
"./index.html",
"./src/**/*.{vue,js,ts}"
],

theme:{
extend:{}
},

plugins:[]

}
EOF



cat > src/style.css <<'EOF'

@tailwind base;
@tailwind components;
@tailwind utilities;


html,
body,
#app{

width:100%;
height:100%;
margin:0;
font-family:
"Tajawal",
"Arial",
sans-serif;

direction:rtl;

background:#f8fafc;

}


*{
box-sizing:border-box;
}


.card{

background:white;

border-radius:16px;

padding:20px;

box-shadow:
0 5px 20px rgba(0,0,0,.06);

}

EOF




echo "[7/10] Creating Frappe API Connector..."


cat > src/api/frappe.ts <<'EOF'

import axios from "axios"


const api = axios.create({

baseURL:"/api",

withCredentials:true,

headers:{
"Content-Type":"application/json"
}

})



export async function getResource(
doctype:string,
params:any={}
){

const res =
await api.get(
"/resource/"+encodeURIComponent(doctype),
{
params
}
)

return res.data.data

}



export async function callMethod(
method:string,
args:any={}
){

const res =
await api.post(
"/method/"+method,
args
)

return res.data.message

}



export async function getCurrentUser(){

return await callMethod(
"frappe.auth.get_logged_user"
)

}


export default api

EOF




echo "[8/10] Creating Permission Store..."

cat > src/stores/permission.ts <<'EOF'

import {defineStore} from "pinia"


export const usePermissionStore =
defineStore("permission",{

state:()=>({

roles:[] as string[],

loaded:false

}),



actions:{


setRoles(r:string[]){

this.roles=r

this.loaded=true

},


hasRole(role:string){

return this.roles.includes(role)

},


canAccess(allowed:string[]){

return allowed.some(
r=>this.roles.includes(r)
)

}


}


})

EOF





echo "[9/10] Creating Router..."

cat > src/router/index.ts <<'EOF'

import {
createRouter,
createWebHistory
}
from "vue-router"


import Dashboard from "../views/Dashboard.vue"
import Envelopes from "../views/Envelopes.vue"
import Certificates from "../views/Certificates.vue"
import Security from "../views/Security.vue"
import Audit from "../views/Audit.vue"



const routes=[


{

path:"/",

redirect:"/dashboard"

},



{

path:"/dashboard",

component:Dashboard

},


{

path:"/envelopes",

component:Envelopes

},


{

path:"/certificates",

component:Certificates

},


{

path:"/security",

component:Security

},


{

path:"/audit",

component:Audit

}



]




export default createRouter({

history:createWebHistory(),

routes

})

EOF





echo "[10/10] Creating Enterprise Layout..."

cat > src/layouts/EnterpriseLayout.vue <<'EOF'

<template>


<div class="min-h-screen flex">


<aside
class="w-72 bg-slate-900 text-white p-5">


<h1 class="text-2xl font-bold mb-8">

Surhan Signature

</h1>



<nav class="space-y-3">


<RouterLink
to="/dashboard"
class="block p-3 rounded hover:bg-slate-700">

لوحة التحكم

</RouterLink>



<RouterLink
to="/envelopes"
class="block p-3 rounded hover:bg-slate-700">

طلبات التوقيع

</RouterLink>



<RouterLink
to="/certificates"
class="block p-3 rounded hover:bg-slate-700">

الشهادات

</RouterLink>



<RouterLink
to="/audit"
class="block p-3 rounded hover:bg-slate-700">

سجل التدقيق

</RouterLink>



<RouterLink
to="/security"
class="block p-3 rounded hover:bg-slate-700">

مركز الأمان

</RouterLink>



</nav>


</aside>




<main class="flex-1 p-8">


<slot></slot>


</main>



</div>


</template>


EOF

echo "[11/15] Creating Vue Pages..."



cat > src/views/Dashboard.vue <<'EOF'

<template>

<div>

<h1 class="text-3xl font-bold mb-6">
لوحة التحكم الرئيسية
</h1>


<div class="grid grid-cols-1 md:grid-cols-4 gap-5">


<div class="card">
<h3>طلبات التوقيع</h3>
<p class="text-3xl font-bold">
{{data.signature_requests || 0}}
</p>
</div>


<div class="card">
<h3>الشهادات</h3>
<p class="text-3xl font-bold">
{{data.certificates || 0}}
</p>
</div>


<div class="card">
<h3>المخاطر</h3>
<p class="text-3xl font-bold">
{{data.risk_count || 0}}
</p>
</div>


<div class="card">
<h3>الحالة</h3>
<p class="text-xl">
{{data.system_status || "Ready"}}
</p>
</div>


</div>


</div>

</template>



<script setup lang="ts">

import {onMounted,ref} from "vue"

import {callMethod} from "../api/frappe"


const data:any=ref({})


onMounted(async()=>{

data.value =
await callMethod(
"surhan_signature.api.signature_dashboard_summary",
{
limit:30
}
)


})


</script>

EOF






cat > src/views/Envelopes.vue <<'EOF'


<template>

<div>

<h1 class="text-3xl font-bold mb-6">
طلبات التوقيع
</h1>


<div class="card">


<table class="w-full">


<thead>

<tr>

<th>العنوان</th>

<th>الحالة</th>

<th>المستوى</th>

<th>التاريخ</th>

</tr>

</thead>


<tbody>


<tr
v-for="item in envelopes"
:key="item.name"
>


<td>
{{item.title}}
</td>


<td>
{{item.status}}
</td>


<td>
{{item.signing_level}}
</td>


<td>
{{item.sent_on}}
</td>


</tr>


</tbody>


</table>


</div>


</div>


</template>




<script setup lang="ts">


import {ref,onMounted} from "vue"

import {getResource} from "../api/frappe"


const envelopes:any=ref([])



onMounted(async()=>{


envelopes.value =
await getResource(
"E-Sign Envelope",
{
fields:JSON.stringify([
"name",
"title",
"status",
"signing_level",
"sent_on"
]),

limit_page_length:50

}

)


})


</script>


EOF






cat > src/views/Certificates.vue <<'EOF'


<template>


<div>


<h1 class="text-3xl font-bold mb-6">
الشهادات الرقمية
</h1>


<div class="card">


<table class="w-full">

<thead>

<tr>

<th>
رقم الشهادة
</th>

<th>
التاريخ
</th>

<th>
Hash
</th>

</tr>

</thead>



<tbody>


<tr
v-for="c in certificates"
:key="c.name"
>


<td>
{{c.certificate_no}}
</td>


<td>
{{c.completed_at}}
</td>


<td>
{{c.final_hash}}
</td>


</tr>


</tbody>


</table>


</div>



</div>


</template>




<script setup lang="ts">


import {ref,onMounted} from "vue"

import {getResource} from "../api/frappe"


const certificates:any=ref([])



onMounted(async()=>{


certificates.value =
await getResource(
"E-Sign Certificate",
{

fields:JSON.stringify([

"name",
"certificate_no",
"completed_at",
"final_hash"

]),

limit_page_length:50

}

)


})


</script>


EOF







cat > src/views/Audit.vue <<'EOF'


<template>


<div>


<h1 class="text-3xl font-bold mb-6">
سجل التدقيق
</h1>



<div
v-for="log in logs"
:key="log.name"
class="card mb-4"
>


<div class="font-bold">

{{log.event_type}}

</div>


<div>

{{log.actor_email}}

</div>


<div>

{{log.timestamp_utc}}

</div>


</div>



</div>


</template>




<script setup lang="ts">


import {ref,onMounted} from "vue"

import {getResource} from "../api/frappe"


const logs:any=ref([])



onMounted(async()=>{


logs.value =
await getResource(
"E-Sign Audit Log",
{

fields:JSON.stringify([

"name",
"event_type",
"actor_email",
"timestamp_utc"

]),


limit_page_length:100


}

)


})


</script>


EOF







cat > src/views/Security.vue <<'EOF'


<template>


<div>


<h1 class="text-3xl font-bold mb-6">
مركز الأمان
</h1>



<div
v-for="event in events"
:key="event.name"
class="card mb-4"
>


<div>

<strong>
{{event.severity}}
</strong>

</div>


<div>

{{event.event_type}}

</div>


<div>

{{event.ip_address}}

</div>


</div>



</div>


</template>




<script setup lang="ts">


import {ref,onMounted} from "vue"

import {getResource} from "../api/frappe"


const events:any=ref([])



onMounted(async()=>{


events.value =
await getResource(
"E-Sign Security Event",
{

fields:JSON.stringify([

"name",
"event_type",
"severity",
"ip_address"

]),


limit_page_length:100


}

)


})


</script>


EOF
echo "[12/15] Creating Main Vue Application..."



cat > src/App.vue <<'EOF'

<template>

<EnterpriseLayout>

<RouterView />

</EnterpriseLayout>


</template>



<script setup lang="ts">

import EnterpriseLayout from "./layouts/EnterpriseLayout.vue"

</script>


EOF





cat > src/main.ts <<'EOF'


import {createApp} from "vue"

import {createPinia} from "pinia"

import App from "./App.vue"

import router from "./router"

import "./style.css"



const app=createApp(App)


app.use(createPinia())

app.use(router)


app.mount("#app")

EOF






echo "[13/15] Creating Frappe Bridge..."



cd $APP_PATH



mkdir -p surhan_signature/www/signature-center



cat > surhan_signature/www/signature-center.py <<'EOF'


import frappe


def get_context(context):

    if frappe.session.user == "Guest":

        frappe.local.flags.redirect_location = (
            "/login?redirect-to=/signature-center"
        )

        raise frappe.Redirect



    context.no_cache = 1

EOF






cat > surhan_signature/www/signature-center.html <<'EOF'


{% extends "templates/web.html" %}


{% block page_content %}


<div id="app"></div>


<script type="module"
src="/assets/surhan_signature/frontend/signature-center/assets/index.js">
</script>


{% endblock %}


EOF






echo "[14/15] Updating hooks..."



HOOK="$APP_PATH/surhan_signature/hooks.py"


if ! grep -q "signature-center" "$HOOK"
then

cat >> "$HOOK" <<'EOF'


web_include_css = [
"/assets/surhan_signature/frontend/signature-center/assets/index.css"
]


web_include_js = [
"/assets/surhan_signature/frontend/signature-center/assets/index.js"
]


EOF

fi






echo "[15/15] Building Vue Application..."



cd $FRONTEND_PATH


npm run build




echo "Copying Vue assets..."


mkdir -p \
$APP_PATH/surhan_signature/public/frontend/signature-center/assets



cp -r dist/assets/* \
$APP_PATH/surhan_signature/public/frontend/signature-center/assets/





echo "Building Frappe assets..."


cd /home/frappe/frappe-bench


bench build --app surhan_signature



echo "Clearing cache..."

bench --site $SITE clear-cache


echo "Restarting bench..."

bench restart



echo "====================================="
echo " Installation Completed Successfully "
echo " Open:"
echo "/signature-center"
echo "====================================="
