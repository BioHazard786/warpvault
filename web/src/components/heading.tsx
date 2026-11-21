/** Page title + one-line subtitle, used at the top of every route. */
export function Heading({ title, children }: { title: string; children: string }) {
  return (
    <section className="flex flex-col gap-2">
      <h1 className="font-serif text-2xl tracking-tight text-balance sm:text-3xl">{title}</h1>
      <p className="text-base leading-relaxed text-pretty text-muted-foreground">{children}</p>
    </section>
  )
}
