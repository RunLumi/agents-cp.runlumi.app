import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "@/app";
import { AppErrorBoundary } from "@/error-boundary";
import "@/styles/globals.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Root element #root was not found.");
}

createRoot(root).render(
  <StrictMode>
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  </StrictMode>,
);
