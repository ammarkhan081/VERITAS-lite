import { useState } from "react";
import { LoaderCircle, Trash2 } from "lucide-react";
import { ApiError, api } from "../api";
import { Button, Dialog } from "./ui";

export default function DeleteCampaignDialog({
  campaignId,
  onClose,
  onDeleted,
}: {
  campaignId: string;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");
  const close = () => { if (!deleting) onClose(); };

  async function deleteCampaign() {
    setDeleting(true);
    setError("");
    try {
      await api.deleteCampaignRecord(campaignId);
      onDeleted();
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "Campaign could not be deleted.");
      setDeleting(false);
    }
  }

  return (
    <Dialog title="Delete campaign permanently?" description="This action cannot be undone." onClose={close}>
      <div className="confirm-copy">
        <p>Campaign <code>{campaignId}</code> and its evaluation history will be permanently removed.</p>
        <p>This includes its traces, attacks, patches, and regression records.</p>
        {error && <div className="inline-error" role="alert">{error}</div>}
      </div>
      <div className="dialog-actions">
        <Button variant="quiet" onClick={close} disabled={deleting}>Keep campaign</Button>
        <Button variant="danger" onClick={() => void deleteCampaign()} disabled={deleting}>
          {deleting ? <><LoaderCircle size={15} className="spin-subtle" /> Deleting</> : <><Trash2 size={15} /> Delete campaign</>}
        </Button>
      </div>
    </Dialog>
  );
}
