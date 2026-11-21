import { CopyAction } from "@/components/copy-action"
import { QrAction } from "@/components/qr-action"
import {
  Attachment,
  AttachmentAction,
  AttachmentActions,
  AttachmentContent,
  AttachmentDescription,
  AttachmentMedia,
  AttachmentTitle,
} from "@/components/ui/attachment"
import { Button } from "@/components/ui/button"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { deleteSecret } from "@/lib/api"
import { expiresIn } from "@/lib/format"
import { clearHistory, removeHistory, useHistory, type HistoryRecord } from "@/lib/history"
import { IconFlame, IconHistory, IconLock, IconTrash } from "@tabler/icons-react"
import { useState } from "react"

function Row({ r }: { r: HistoryRecord }) {
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  return (
    <Attachment state={error ? "error" : "done"} className="w-full" title={r.id}>
      <AttachmentMedia>{r.burn ? <IconFlame /> : <IconLock />}</AttachmentMedia>
      <AttachmentContent>
        <AttachmentTitle className="font-mono">{r.id}</AttachmentTitle>
        <AttachmentDescription className="font-mono tabular-nums">
          {error
            ? `Delete failed · ${error}`
            : [r.burn ? "Burn after reading" : "Timed", expiresIn(r.expiresAt)]
                .filter(Boolean)
                .join(" · ")}
        </AttachmentDescription>
      </AttachmentContent>
      <AttachmentActions>
        <CopyAction value={r.shareUrl} label={`Copy link for ${r.id}`} />
        <QrAction value={r.shareUrl} label={`QR code for ${r.id}`} />
        <AttachmentAction
          aria-label={`Destroy ${r.id} on the server`}
          title="Destroy now"
          disabled={busy}
          onClick={async () => {
            setBusy(true)
            try {
              if (r.deleteToken) await deleteSecret(r.id, r.deleteToken)
              removeHistory(r.id)
            } catch (e) {
              setError((e as Error).message)
              setBusy(false)
            }
          }}
        >
          <IconTrash />
        </AttachmentAction>
      </AttachmentActions>
    </Attachment>
  )
}

export function HistorySheet() {
  const history = useHistory()
  return (
    <Sheet>
      <SheetTrigger render={<Button variant="outline" size="icon" aria-label="Secret history" />}>
        <IconHistory />
      </SheetTrigger>
      <SheetContent side="right">
        <SheetHeader>
          <SheetTitle>Your secrets</SheetTitle>
          <SheetDescription>
            Links created in this browser, kept here so you can copy or destroy them. Clearing
            history doesn't delete anything from the server.
          </SheetDescription>
        </SheetHeader>
        <div className="flex flex-1 flex-col gap-2.5 overflow-y-auto px-4">
          {history.length === 0 ? (
            <Empty>
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <IconHistory />
                </EmptyMedia>
                <EmptyTitle>No secrets from this browser yet</EmptyTitle>
                <EmptyDescription>Links you create will appear here.</EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            history.map((r) => <Row key={r.id} r={r} />)
          )}
        </div>
        {history.length > 0 && (
          <SheetFooter>
            <Button variant="destructive" onClick={clearHistory}>
              <IconTrash data-icon="inline-start" /> Clear history
            </Button>
          </SheetFooter>
        )}
      </SheetContent>
    </Sheet>
  )
}
