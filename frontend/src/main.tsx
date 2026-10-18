import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/chakra-petch/400.css";
import "@fontsource/chakra-petch/500.css";
import "@fontsource/chakra-petch/600.css";
import "@fontsource/chakra-petch/700.css";
import "@fontsource-variable/jetbrains-mono";
import "./styles/tokens.css";
import "./styles/app.css";
import App from "./App.tsx";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
