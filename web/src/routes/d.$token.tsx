import { Heading } from "@/components/heading"
import { Section } from "@/components/section"
import { Button, buttonVariants } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { destroyByToken } from "@/lib/api"
import { IconArrowLeft, IconTrash } from "@tabler/icons-react"
import { createFileRoute } from "@tanstack/react-router"
import { useState } from "react"

/** The creator's delete link. It asks first: opening a link must never destroy anything, because mail
 *  scanners and chat previews open links on their own. */
export const Route = createFileRoute("/d/$token")({ component: DestroyPage })

function DestroyPage() {
  const { token } = Route.useParams()
  const [state, setState] = useState<"idle" | "busy" | "done" | "gone" | "error">("idle")
  const [error, setError] = useState("")

  const destroy = async () => {
    setState("busy")
    try {
      setState((await destroyByToken(token)) ? "done" : "gone")
    } catch (e) {
      setError((e as Error).message)
      setState("error")
    }
  }

  const finished = state === "done" || state === "gone"
  return (
    <>
      <Heading
        title={
          state === "done"
            ? "Destroyed."
            : state === "gone"
              ? "Already gone."
              : "Destroy this secret?"
        }
      >
        {state === "done"
          ? "The encrypted secret was permanently deleted from the server."
          : state === "gone"
            ? "This secret was already opened, expired or destroyed, or the link is wrong."
            : "This deletes it from the server right now. Anyone with the share link will get a 'burned' page instead."}
      </Heading>
      <Section title="Delete link">
        {state === "error" && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex flex-wrap items-center gap-2">
          {!finished && (
            <Button
              variant="destructive"
              disabled={state === "busy"}
              onClick={() => void destroy()}
            >
              {state === "busy" ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <IconTrash data-icon="inline-start" />
              )}
              Destroy now
            </Button>
          )}
          <a href="/" className={buttonVariants({ variant: "outline" })}>
            <IconArrowLeft data-icon="inline-start" /> Back to home
          </a>
        </div>
      </Section>
    </>
  )
}
