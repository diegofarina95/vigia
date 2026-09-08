import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./index.css";
import { APP_PREFIX } from "./prefix";
import { LangProvider } from "./lib/LangContext";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <LangProvider>
      <BrowserRouter basename={APP_PREFIX}>
        <App />
      </BrowserRouter>
    </LangProvider>
  </StrictMode>,
);
