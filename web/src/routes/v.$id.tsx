import { FileCard } from "@/components/file-card"
import { mimeOf } from "@/components/file-icon"
import { Heading } from "@/components/heading"
import { Section } from "@/components/section"
import { StatusView } from "@/components/status-view"
import { Button, buttonVariants } from "@/components/ui/button"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
  InputGroupText,
  InputGroupTextarea,
} from "@/components/ui/input-group"
import { Spinner } from "@/components/ui/spinner"
import { toast } from "@/components/ui/toast"
import { fetchMeta, openSecret, type Meta } from "@/lib/api"
import { copyText } from "@/lib/clipboard"
import { formatBytes } from "@/lib/format"
import { open, VaultError, type Bytes, type Secret } from "@/lib/vault"
import {
  IconArrowLeft,
  IconCheck,
  IconCopy,
  IconDownload,
  IconEye,
  IconEyeOff,
  IconFlame,
  IconKey,
  IconLock,
  IconLockOpen,
} from "@tabler/icons-react"
import { createFileRoute } from "@tanstack/react-router"
import { useMemo, useState } from "react"

/** The page always loads metadata first (it never burns anything), so a burned/expired link shows its
 *  status right away and a passphrase-protected one can ask for the passphrase before opening. */
export const Route = createFileRoute("/v/$id")({
  loader: ({ params }) => fetchMeta(params.id),
  component: ViewPage,
})

function ViewPage() {
  const meta = Route.useLoaderData()
  const { id } = Route.useParams()
  const [gone, setGone] = useState<number>()
  const status = typeof meta === "number" ? meta : gone
  if (status) return <StatusView code={status} />
  return <Reveal id={id} meta={meta as Meta} onGone={setGone} />
}

function Reveal({
  id,
  meta,
  onGone,
}: {
  id: string
  meta: Meta
  onGone: (status: number) => void
}) {
  const [key, setKey] = useState(() => location.hash.slice(1)) // the fragment never reaches the server
  const [keyFromLink] = useState(() => location.hash.length > 1)
  const [passphrase, setPassphrase] = useState("")
  const [showPass, setShowPass] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  // A burn secret is destroyed server-side the moment it is downloaded, so the ciphertext is kept here:
  // a wrong key or passphrase can then be retried without asking the server again.
  const [blob, setBlob] = useState<Bytes>()
  const [secret, setSecret] = useState<Secret>()

  const canReveal = !busy && key.trim() !== "" && (!meta.passphrase || passphrase !== "")

  async function reveal(e?: React.FormEvent) {
    e?.preventDefault()
    setBusy(true)
    setError("")
    try {
      let data = blob
      if (!data) {
        const res = await openSecret(id)
        if (typeof res === "number") return onGone(res)
        data = res
        setBlob(res)
      }
      setSecret(await open(data, key.trim(), passphrase))
    } catch (err) {
      setError(
        err instanceof VaultError
          ? err.code === "decrypt"
            ? `${err.message} You can try again. ${meta.burn ? "The secret is held in this tab; don't close it." : ""}`
            : err.message
          : (err as Error).message,
      )
    } finally {
      setBusy(false)
    }
  }

  if (secret) return <Revealed secret={secret} burned={meta.burn} />

  return (
    <>
      {meta.burn ? (
        <Heading title="Someone sent you a secret that self-destructs.">
          Revealing it deletes it from the server. Copy what you need before you close the page.
        </Heading>
      ) : (
        <Heading title="Someone shared a secret with you.">
          It is decrypted in your browser; the server only ever holds ciphertext.
        </Heading>
      )}
      <Section
        title={meta.burn ? "Burn after reading" : "Encrypted secret"}
        aside={
          <span className="flex items-center gap-1">
            {meta.burn && (
              <span className="flex items-center gap-1 text-destructive">
                <IconFlame className="size-3.5" /> single use
              </span>
            )}
            <span>{formatBytes(meta.size_bytes)}</span>
          </span>
        }
      >
        <form onSubmit={reveal} className="flex flex-col gap-3">
          {!keyFromLink && (
            <InputGroup>
              <InputGroupAddon>
                <IconKey />
              </InputGroupAddon>
              <InputGroupInput
                autoFocus
                placeholder="Key from the link (the part after #)"
                aria-label="Decryption key"
                autoComplete="off"
                spellCheck={false}
                value={key}
                onChange={(e) => setKey(e.target.value)}
              />
            </InputGroup>
          )}
          {meta.passphrase && (
            <InputGroup>
              <InputGroupAddon>
                <IconLock />
              </InputGroupAddon>
              <InputGroupInput
                type={showPass ? "text" : "password"}
                autoFocus={keyFromLink}
                placeholder="Passphrase (the sender set one)"
                aria-label="Passphrase"
                autoComplete="off"
                aria-invalid={!!error}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
              />
              <InputGroupAddon align="inline-end">
                <InputGroupButton
                  size="icon-xs"
                  aria-label={showPass ? "Hide passphrase" : "Show passphrase"}
                  onClick={() => setShowPass((v) => !v)}
                >
                  {showPass ? <IconEyeOff /> : <IconEye />}
                </InputGroupButton>
              </InputGroupAddon>
            </InputGroup>
          )}
          {error && <p className="text-xs text-destructive">{error}</p>}
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="submit"
              variant={meta.burn ? "destructive" : "default"}
              disabled={!canReveal}
            >
              {busy ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <IconLockOpen data-icon="inline-start" />
              )}
              {busy ? "Decrypting…" : meta.burn && !blob ? "Reveal & destroy" : "Reveal"}
            </Button>
            <a href="/" className={buttonVariants({ variant: "outline" })}>
              <IconArrowLeft data-icon="inline-start" /> Back to home
            </a>
          </div>
        </form>
      </Section>
    </>
  )
}

function Revealed({ secret, burned }: { secret: Secret; burned: boolean }) {
  const [hidden, setHidden] = useState(false)
  const [copied, setCopied] = useState(false)
  const text = useMemo(
    () => (secret.kind === "text" ? new TextDecoder().decode(secret.data) : ""),
    [secret],
  )
  // the MIME type lets images render in the preview
  const blob = useMemo(() => new Blob([secret.data], { type: mimeOf(secret.name, "") }), [secret])

  const download = () => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = secret.name.replace(/[\\/\0]/g, "_") || "secret.bin"
    document.body.append(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const copy = async () => {
    if (await copyText(text)) {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } else {
      toast.add({
        type: "error",
        title: "Couldn't copy",
        description: "Select the text and copy it by hand.",
      })
    }
  }

  return (
    <>
      <Heading title={burned ? "It's yours. It's gone from the server." : "Decrypted."}>
        {burned
          ? "This link no longer works. Save what you need from this page."
          : "Decrypted in your browser. The server never saw it."}
      </Heading>
      <Section
        title={secret.kind === "file" ? "File" : "Secret"}
        aside={
          burned ? (
            <span className="flex items-center gap-1 text-destructive">
              <IconFlame className="size-3.5" /> destroyed
            </span>
          ) : undefined
        }
      >
        {secret.kind === "text" ? (
          <InputGroup>
            <InputGroupAddon align="block-start" className="border-b">
              <InputGroupText>
                <IconLockOpen />
                Decrypted in your browser
              </InputGroupText>
              <InputGroupButton
                size="icon-xs"
                className="ml-auto"
                aria-label={hidden ? "Show secret" : "Hide secret"}
                title={hidden ? "Show" : "Hide"}
                onClick={() => setHidden((h) => !h)}
              >
                {hidden ? <IconEye /> : <IconEyeOff />}
              </InputGroupButton>
              <InputGroupButton
                size="icon-xs"
                aria-label={copied ? "Copied" : "Copy secret"}
                title={copied ? "Copied" : "Copy"}
                onClick={() => void copy()}
              >
                {copied ? <IconCheck /> : <IconCopy />}
              </InputGroupButton>
            </InputGroupAddon>
            <InputGroupTextarea
              readOnly
              className="max-h-96 min-h-32 font-mono"
              aria-label="Decrypted secret"
              spellCheck={false}
              value={hidden ? "•".repeat(Math.min(text.length, 40)) : text}
            />
            <InputGroupAddon align="block-end" className="border-t">
              <InputGroupText className="font-mono text-xs tabular-nums">
                {text.length.toLocaleString()} characters ·{" "}
                {text.split("\n").length.toLocaleString()} lines
              </InputGroupText>
            </InputGroupAddon>
          </InputGroup>
        ) : (
          <>
            <FileCard name={secret.name} blob={blob} />
            <div>
              <Button onClick={download}>
                <IconDownload data-icon="inline-start" /> Download
              </Button>
            </div>
          </>
        )}
      </Section>
      <div>
        <a href="/" className={buttonVariants({ variant: "outline" })}>
          <IconArrowLeft data-icon="inline-start" /> Share a new secret
        </a>
      </div>
    </>
  )
}
