import { AsciiLogo } from "@/components/ascii-logo"
import { CliBox } from "@/components/cli-box"
import { Dropzone } from "@/components/dropzone"
import { FileCard } from "@/components/file-card"
import { Heading } from "@/components/heading"
import { QR } from "@/components/qr"
import { Section } from "@/components/section"
import { AttachmentAction } from "@/components/ui/attachment"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
  InputGroupText,
  InputGroupTextarea,
} from "@/components/ui/input-group"
import { Input } from "@/components/ui/input"
import { Marker, MarkerContent, MarkerIcon } from "@/components/ui/marker"
import { Spinner } from "@/components/ui/spinner"
import { toast } from "@/components/ui/toast"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { createSecret, deleteSecret, fetchInfo, type Created } from "@/lib/api"
import { formatBytes } from "@/lib/format"
import { addHistory } from "@/lib/history"
import { newKey, seal, sealedSize, type Secret } from "@/lib/vault"
import {
  IconClipboard,
  IconEye,
  IconEyeOff,
  IconFlame,
  IconLock,
  IconLockPlus,
  IconPlus,
  IconShieldLock,
  IconTrash,
  IconX,
} from "@tabler/icons-react"
import { createFileRoute } from "@tanstack/react-router"
import { useState } from "react"

export const Route = createFileRoute("/")({ loader: fetchInfo, component: CreatePage })

const TOKEN_KEY = "warpvault_token"

type Result = { created: Created; link: string; passphrase: boolean }

function CreatePage() {
  const info = Route.useLoaderData()
  const maxBytes = info.max_secret_size_mb * 1024 * 1024
  const expiries = info.allowed_expiries

  const [mode, setMode] = useState<"text" | "file">("text")
  const [text, setText] = useState("")
  const [file, setFile] = useState<File>()
  const [expiry, setExpiry] = useState(
    expiries.includes(info.default_expiry) ? info.default_expiry : (expiries[0] ?? "burn"),
  )
  const [passphrase, setPassphrase] = useState("")
  const [showPass, setShowPass] = useState(false)
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) ?? "")
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<Result>()

  const textBytes = new TextEncoder().encode(text).length
  const tooBig = mode === "text" && sealedSize({ name: "", data: { length: textBytes } }) > maxBytes

  const onFiles = (files: File[]) => {
    const f = files[0]
    if (!f) return
    const size = sealedSize({ name: f.name, data: { length: f.size } })
    if (size > maxBytes) {
      toast.add({
        type: "error",
        title: "That file is too big",
        description: `The limit is ${info.max_secret_size_mb} MB including encryption overhead; this is ${formatBytes(size)}.`,
      })
      return
    }
    setFile(f)
  }

  const paste = async () => {
    try {
      setText(await navigator.clipboard.readText())
    } catch {
      toast.add({
        type: "error",
        title: "Couldn't read the clipboard",
        description: "Paste into the box with Ctrl+V instead.",
      })
    }
  }

  const ready = !busy && !tooBig && (mode === "text" ? text.length > 0 : !!file)

  async function create() {
    setBusy(true)
    try {
      const secret: Secret =
        mode === "text"
          ? { kind: "text", name: "", data: new TextEncoder().encode(text) }
          : { kind: "file", name: file!.name, data: new Uint8Array(await file!.arrayBuffer()) }
      const key = newKey()
      const blob = await seal(secret, key, passphrase)
      const created = await createSecret(blob, expiry, token)
      const link = `${location.origin}/v/${created.id}#${key}`
      addHistory({
        id: created.id,
        shareUrl: link,
        burn: created.burn,
        createdAt: created.created_at,
        expiresAt: created.expires_at,
        deleteToken: created.delete_token,
      })
      setResult({ created, link, passphrase: passphrase !== "" })
      setText("")
      setFile(undefined)
      setPassphrase("")
    } catch (e) {
      toast.add({
        type: "error",
        title: "Couldn't create the link",
        description: (e as Error).message,
      })
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <section className="flex flex-col gap-5">
        <AsciiLogo />
        <Heading title="Share a secret. Let it disappear.">
          Passwords, keys and files, encrypted in your browser so the server never sees them. The
          key lives in the link's #fragment and never leaves your device.
        </Heading>
      </section>

      {result ? (
        <ResultView result={result} onReset={() => setResult(undefined)} />
      ) : (
        <>
          <Section
            title="Secret"
            aside={
              <ToggleGroup
                variant="outline"
                size="sm"
                spacing={0}
                value={[mode]}
                onValueChange={(v) => v[0] && setMode(v[0] as "text" | "file")}
                aria-label="Kind of secret"
              >
                <ToggleGroupItem value="text" className="font-mono text-xs">
                  Text
                </ToggleGroupItem>
                <ToggleGroupItem value="file" className="font-mono text-xs">
                  File
                </ToggleGroupItem>
              </ToggleGroup>
            }
          >
            {mode === "text" ? (
              <InputGroup>
                <InputGroupAddon align="block-start" className="border-b">
                  <InputGroupText>
                    <IconShieldLock />
                    Encrypted before it leaves this tab
                  </InputGroupText>
                  <InputGroupButton
                    size="icon-xs"
                    className="ml-auto"
                    aria-label="Paste from clipboard"
                    title="Paste from clipboard"
                    onClick={() => void paste()}
                  >
                    <IconClipboard />
                  </InputGroupButton>
                  <InputGroupButton
                    size="icon-xs"
                    aria-label="Clear"
                    title="Clear"
                    disabled={!text}
                    onClick={() => setText("")}
                  >
                    <IconX />
                  </InputGroupButton>
                </InputGroupAddon>
                <InputGroupTextarea
                  autoFocus
                  className="min-h-52 font-mono"
                  placeholder="Paste an API key, a .env file, a password, a note…"
                  aria-label="Secret text"
                  spellCheck={false}
                  aria-invalid={tooBig}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                />
                <InputGroupAddon align="block-end" className="border-t">
                  <InputGroupText className="font-mono text-xs tabular-nums">
                    {text.length.toLocaleString()} characters ·{" "}
                    {(text ? text.split("\n").length : 0).toLocaleString()} lines
                  </InputGroupText>
                  <InputGroupText
                    className={`ml-auto font-mono text-xs tabular-nums ${tooBig ? "text-destructive" : ""}`}
                  >
                    {formatBytes(textBytes)} / {info.max_secret_size_mb} MB
                  </InputGroupText>
                </InputGroupAddon>
              </InputGroup>
            ) : file ? (
              <FileCard
                name={file.name}
                blob={file}
                actions={
                  <AttachmentAction aria-label="Remove file" onClick={() => setFile(undefined)}>
                    <IconX />
                  </AttachmentAction>
                }
              />
            ) : (
              <Dropzone
                onFiles={onFiles}
                hints={[`up to ${info.max_secret_size_mb} MB`, "one file"]}
              />
            )}
          </Section>

          <Section
            title="Self-destruct"
            aside={
              <ToggleGroup
                variant="outline"
                size="sm"
                spacing={0}
                value={[expiry]}
                onValueChange={(v) => v[0] && setExpiry(v[0])}
                aria-label="When the secret is destroyed"
              >
                {expiries.map((e) =>
                  e === "burn" ? (
                    <ToggleGroupItem
                      key={e}
                      value={e}
                      title="Destroyed the first time it is opened"
                      className="font-mono text-xs text-destructive/80 hover:text-destructive data-pressed:border-destructive/40 data-pressed:bg-destructive/15 data-pressed:text-destructive"
                    >
                      <IconFlame /> Burn
                    </ToggleGroupItem>
                  ) : (
                    <ToggleGroupItem key={e} value={e} className="font-mono text-xs">
                      {e}
                    </ToggleGroupItem>
                  ),
                )}
              </ToggleGroup>
            }
          >
            <p className="text-sm text-muted-foreground">
              {expiry === "burn"
                ? "Destroyed the first time it is opened. If nobody opens it, it still expires after 72 hours."
                : `Destroyed ${expiry} from now, however often it is opened.`}
            </p>
          </Section>

          <Section title="Passphrase" aside="optional">
            <InputGroup>
              <InputGroupAddon>
                <IconLock />
              </InputGroupAddon>
              <InputGroupInput
                type={showPass ? "text" : "password"}
                placeholder="The recipient must enter it too"
                aria-label="Passphrase"
                autoComplete="new-password"
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
            <p className="text-xs text-muted-foreground">
              Mixed into the encryption key. Send it over a different channel than the link.
            </p>
          </Section>

          {info.auth_required && (
            <Section title="Upload token">
              <Input
                type="password"
                placeholder="This server requires one to create secrets"
                aria-label="Upload token"
                value={token}
                onChange={(e) => {
                  setToken(e.target.value)
                  localStorage.setItem(TOKEN_KEY, e.target.value)
                }}
              />
            </Section>
          )}

          <div className="flex justify-end">
            <Button disabled={!ready} onClick={() => void create()}>
              {busy ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <IconLockPlus data-icon="inline-start" />
              )}
              {busy ? "Encrypting…" : "Encrypt & create link"}
            </Button>
          </div>
        </>
      )}

      <Terminal />
    </>
  )
}

function ResultView({ result, onReset }: { result: Result; onReset: () => void }) {
  const { created, link, passphrase } = result
  const [armed, setArmed] = useState(false)
  const [gone, setGone] = useState(false)
  const [busy, setBusy] = useState(false)

  const destroy = async () => {
    setBusy(true)
    try {
      await deleteSecret(created.id, created.delete_token)
      setGone(true)
    } catch (e) {
      toast.add({ type: "error", title: "Couldn't destroy it", description: (e as Error).message })
    } finally {
      setBusy(false)
      setArmed(false)
    }
  }

  return (
    <Section
      title={gone ? "Destroyed" : "Share"}
      aside={
        created.burn ? "single use" : `expires ${new Date(created.expires_at).toLocaleString()}`
      }
    >
      <Card>
        {gone ? (
          <CardContent>
            <p className="py-6 text-center text-sm text-muted-foreground">
              The secret was deleted from the server. The link no longer works.
            </p>
          </CardContent>
        ) : (
          <CardContent className="flex flex-col gap-6 sm:flex-row sm:items-center">
            <QR value={link} className="self-center sm:self-auto" />
            <div className="flex min-w-0 flex-1 flex-col gap-4">
              <div className="flex flex-col gap-1">
                <span className="font-mono text-xs tracking-wider text-muted-foreground uppercase">
                  Link
                </span>
                <CliBox command={link} prompt={false} />
              </div>
              <div className="flex flex-col gap-1">
                <span className="font-mono text-xs tracking-wider text-muted-foreground uppercase">
                  From a terminal
                </span>
                <CliBox command={`warpvault get "${link}"`} />
              </div>
            </div>
          </CardContent>
        )}
        <CardFooter>
          <Marker className="text-xs">
            <MarkerIcon>
              <IconLock />
            </MarkerIcon>
            <MarkerContent>
              {gone
                ? "Nothing readable was ever on the server, and now nothing is."
                : `Everything after the # stays on your device: without it the link is useless, even to us. ${
                    passphrase ? "Send the passphrase over a different channel. " : ""
                  }${created.burn ? "It is destroyed the first time it is opened." : ""}`}
            </MarkerContent>
          </Marker>
        </CardFooter>
      </Card>
      <div className="flex flex-wrap items-center gap-2">
        {!gone && (
          <>
            {!created.burn && (
              <a
                href={link}
                target="_blank"
                rel="noreferrer"
                className={buttonVariants({ variant: "outline", size: "sm" })}
              >
                Test link
              </a>
            )}
            <Button
              variant={armed ? "destructive" : "outline"}
              size="sm"
              disabled={busy}
              onClick={() => (armed ? void destroy() : setArmed(true))}
              onBlur={() => setArmed(false)}
            >
              {busy ? <Spinner data-icon="inline-start" /> : <IconTrash data-icon="inline-start" />}
              {armed ? "Click again to destroy" : "Destroy now"}
            </Button>
          </>
        )}
        <Button size="sm" className="ml-auto" onClick={onReset}>
          <IconPlus data-icon="inline-start" /> New secret
        </Button>
      </div>
    </Section>
  )
}

function Terminal() {
  const origin = location.origin
  const CLI = {
    install: {
      cmd: `curl -fsSL ${origin}/install.sh | bash`,
      hint: "Installs the warpvault CLI and points it at this server. Linux, macOS and Windows (Git Bash).",
    },
    send: {
      cmd: `echo "sk_live_999" | warpvault`,
      hint: `Encrypts locally and prints a link. Add -e 24h to keep it instead of burning, -p for a passphrase, or -f <file> to send a file. Not installed from this page? Run: warpvault config set server ${origin}`,
    },
    get: {
      cmd: `warpvault get "${origin}/v/a8X2mP9z#KEY"`,
      hint: "Decrypts locally. Text goes to stdout; files are saved under their original name.",
    },
  }
  const [tab, setTab] = useState<keyof typeof CLI>("install")
  return (
    <Section
      title="Terminal"
      aside={
        <ToggleGroup
          variant="outline"
          size="sm"
          spacing={0}
          value={[tab]}
          onValueChange={(v) => v[0] && setTab(v[0] as keyof typeof CLI)}
          aria-label="Command"
        >
          {Object.keys(CLI).map((k) => (
            <ToggleGroupItem key={k} value={k} className="font-mono text-xs">
              {k}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
      }
    >
      <CliBox command={CLI[tab].cmd} />
      <p className="text-xs text-muted-foreground">{CLI[tab].hint}</p>
    </Section>
  )
}
