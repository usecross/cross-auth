import { createDocsServer } from "@usecross/docs/ssr";
import { DocsPage } from "./pages/DocsPage";

createDocsServer({
  pages: {
    "docs/DocsPage": DocsPage,
  },
  title: (title) => `${title} - Cross Auth`,
});
