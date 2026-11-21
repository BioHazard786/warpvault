import { FileIcon, fileKind, isImage } from "@/components/file-icon"
import {
  Attachment,
  AttachmentActions,
  AttachmentContent,
  AttachmentDescription,
  AttachmentMedia,
  AttachmentTitle,
} from "@/components/ui/attachment"
import { formatBytes } from "@/lib/format"
import { useEffect, useState, type ReactNode } from "react"

/** An object URL for `blob`, revoked when the blob changes or the component unmounts. */
function useObjectUrl(blob: Blob | undefined) {
  const [url, setUrl] = useState<string>()
  useEffect(() => {
    if (!blob) return setUrl(undefined)
    const u = URL.createObjectURL(blob)
    setUrl(u)
    return () => URL.revokeObjectURL(u)
  }, [blob])
  return url
}

/** A file as an attachment row. Images get a thumbnail (attachment image mode).
 *  The blob must carry the right MIME type for the image to render. */
export function FileCard({
  name,
  blob,
  actions,
}: {
  name: string
  blob: Blob
  /** attachment actions, e.g. a remove button */
  actions?: ReactNode
}) {
  const image = isImage(name, blob.type)
  const url = useObjectUrl(image ? blob : undefined)
  return (
    <Attachment state="idle" className="w-full">
      <AttachmentMedia variant={url ? "image" : "icon"}>
        {url ? <img src={url} alt="" /> : <FileIcon name={name} type={blob.type} />}
      </AttachmentMedia>
      <AttachmentContent>
        <AttachmentTitle title={name}>{name}</AttachmentTitle>
        <AttachmentDescription className="font-mono">
          {fileKind(name, blob.type)} · {formatBytes(blob.size)}
        </AttachmentDescription>
      </AttachmentContent>
      {actions && <AttachmentActions>{actions}</AttachmentActions>}
    </Attachment>
  )
}
