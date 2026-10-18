import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

/*
 * Toute la communication passe par ce proxy : le navigateur ne parle qu'à l'origine
 * du frontend, et le jeton d'API (CYBERMORPH_API_TOKEN) est ajouté ici, côté serveur,
 * sans jamais être inclus dans le bundle envoyé au navigateur.
 *
 * Variables (shell ou frontend/.env, sans préfixe VITE_ donc non exposées) :
 *   CYBERMORPH_API_URL    cible du backend        (défaut http://127.0.0.1:8000)
 *   CYBERMORPH_UI_HOST    interface d'écoute       (défaut 127.0.0.1, local uniquement)
 *   CYBERMORPH_API_TOKEN  jeton transmis au backend (optionnel)
 */
export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), "CYBERMORPH_"), ...process.env };

  const target = env.CYBERMORPH_API_URL || "http://127.0.0.1:8000";
  const host = env.CYBERMORPH_UI_HOST || "127.0.0.1";
  const headers: Record<string, string> = env.CYBERMORPH_API_TOKEN
    ? { Authorization: `Bearer ${env.CYBERMORPH_API_TOKEN}` }
    : {};

  const proxy = {
    "/api": { target, changeOrigin: true, headers },
    "/ws": { target, changeOrigin: true, ws: true, headers },
  };

  return {
    plugins: [react()],
    server: { host, proxy },
    preview: { host, proxy },
    build: {
      chunkSizeWarningLimit: 1600,
      rolldownOptions: {
        output: {
          // La 3D est isolée par l'import dynamique de TwinScene ; React reste dans un chunk à part
          // pour ne pas être fusionné avec les dépendances 3D (sinon l'entrée chargerait tout three.js).
          advancedChunks: {
            groups: [{ name: "react", test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ }],
          },
        },
      },
    },
  };
});
