import { Link } from "@inertiajs/react"

import { Grid, Hero, Section } from "../../components/ui"
import { SitePage } from "../../layouts"
import type { TwoFactorProps } from "./shared"

interface Props extends TwoFactorProps {
  codes: string[]
  urls: { done: string }
}

export default function RecoveryCodes({ site, codes, urls }: Props) {
  return (
    <SitePage site={site} title="Recovery codes">
      <Hero eyebrow="Settings" title="Your recovery codes">
        Save these somewhere safe. Each one signs you in once without your
        phone. They are shown only now.
      </Hero>
      <Grid single>
        <Section>
          <ul data-testid="recovery-codes">
            {codes.map((code) => (
              <li key={code}>
                <code>{code}</code>
              </li>
            ))}
          </ul>
          <p>
            <Link href={urls.done}>I saved them</Link>
          </p>
        </Section>
      </Grid>
    </SitePage>
  )
}
