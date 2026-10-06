import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'


export default defineConfig({ base: "/assets/surhan_signature/frontend/signature-center/",

plugins:[
vue()
],

build:{

manifest:true,

outDir:"dist"

}

})
