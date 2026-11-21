import {defineConfig} from 'vite';
import react from '@tailwindcss/vite';
export default defineConfig({plugins:[react()],server:{proxy:{'/api':'http://localhost:8080','/health':'http://localhost:8080'}}});
