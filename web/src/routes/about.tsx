import { AsciiLogo } from "@/components/ascii-logo"
import { Section } from "@/components/section"
import { fetchInfo } from "@/lib/api"
import { IconBrandGithub, IconExternalLink } from "@tabler/icons-react"
import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/about")({ loader: fetchInfo, component: About })

const GITHUB = "https://github.com/BioHazard786"

type App = { name: string; blurb: string; live?: string; repo: string; here?: boolean }

const APPS: App[] = [
  {
    name: "Warpvault",
    blurb:
      "Zero-knowledge secret sharing: encrypted in your browser or terminal, so the server never sees the plaintext.",
    live: "https://vault.warplabs.info",
    repo: `${GITHUB}/warpvault`,
    here: true,
  },
  {
    name: "Warpstash",
    blurb: "Temporary file hosting with expiry, burn-after-reading and optional passwords.",
    live: "https://stash.warplabs.info",
    repo: `${GITHUB}/warpstash`,
  },
  {
    name: "WarpDrop",
    blurb:
      "Privacy-first, self-hostable file sharing from device to device. Like AirDrop, without the cloud.",
    live: "https://drop.warplabs.info",
    repo: `${GITHUB}/warpdrop`,
  },
]

const link = "inline-flex items-center gap-1 underline underline-offset-4 hover:text-foreground"

function About() {
  const info = Route.useLoaderData()
  return (
    <>
      <section className="flex flex-col gap-5">
        <AsciiLogo />
        <div className="flex flex-col gap-2">
          <h1 className="font-serif text-2xl tracking-tight text-balance sm:text-3xl">
            Small tools that do one thing well.
          </h1>
          <p className="text-base leading-relaxed text-pretty text-muted-foreground">
            Warp is a family of open-source, self-hostable utilities. Use the hosted versions, or
            run your own with a single container.
          </p>
        </div>
      </section>

      <Section title="The Warp family">
        <ul className="flex flex-col gap-3">
          {APPS.map((app) => (
            <li
              key={app.name}
              className="flex flex-col gap-2 rounded-2xl border bg-card p-4 text-card-foreground"
            >
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="font-heading text-sm font-medium">{app.name}</h2>
                {app.here && (
                  <span className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                    you are here
                  </span>
                )}
                {!app.live && (
                  <span className="rounded-md border border-dashed px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                    coming soon
                  </span>
                )}
              </div>
              <p className="text-sm leading-relaxed text-muted-foreground">{app.blurb}</p>
              <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-muted-foreground">
                {app.live && (
                  <a href={app.live} target="_blank" rel="noreferrer" className={link}>
                    {app.live.replace("https://", "")} <IconExternalLink className="size-3.5" />
                  </a>
                )}
                <a href={app.repo} target="_blank" rel="noreferrer" className={link}>
                  <IconBrandGithub className="size-3.5" /> source
                </a>
              </div>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="The developer">
        <p className="text-sm leading-relaxed text-muted-foreground">
          Built and maintained by Mohd Zaid (
          <a href={GITHUB} target="_blank" rel="noreferrer" className={link}>
            @BioHazard786
          </a>
          ). Everything here is open source: bug reports, ideas and pull requests are welcome.
        </p>
      </Section>

      <Section title="This server" aside={info.version}>
        <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 font-mono text-xs">
          <dt className="text-muted-foreground">max secret size</dt>
          <dd>{info.max_secret_size_mb} MB</dd>
          <dt className="text-muted-foreground">lifetimes</dt>
          <dd>{info.allowed_expiries.join(", ")}</dd>
          <dt className="text-muted-foreground">upload token</dt>
          <dd>{info.auth_required ? "required" : "not required"}</dd>
        </dl>
      </Section>
    </>
  )
}
