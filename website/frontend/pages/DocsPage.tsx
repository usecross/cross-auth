import { DocsLayout, Markdown } from "@usecross/docs";

interface DocsPageProps {
  content: {
    title: string;
    description: string;
    body: string;
  };
}

export function DocsPage({ content }: DocsPageProps) {
  // Logo, githubUrl, and navLinks come from shared props via pyproject.toml config
  return (
    <DocsLayout title={content?.title ?? ""} description={content?.description}>
      <Markdown content={content?.body ?? ""} />
    </DocsLayout>
  );
}
