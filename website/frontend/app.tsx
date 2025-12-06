import { createDocsApp } from "@usecross/docs";
import { DocsPage } from "./pages/DocsPage";
import "./globals.css";

createDocsApp({
  pages: {
    "docs/DocsPage": DocsPage,
  },
  title: (title) => `${title} - Cross Auth`,
});
