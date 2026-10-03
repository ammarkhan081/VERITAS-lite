import { useState, type FormEvent } from "react";
import { ArrowRight, LoaderCircle, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api";
import type { CampaignCreateRequest } from "../types";
import { Button, Dialog } from "./ui";

export default function CreateCampaignDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const [maxSteps, setMaxSteps] = useState(20);
  const [maxTokens, setMaxTokens] = useState(50000);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    const body: CampaignCreateRequest = {
      sut_descriptor: { type: "custom_sut", tools: ["web_search", "file_write", "send_message"] },
      threat_model: { families: ["direct_injection", "indirect_injection", "goal_hijack"] },
      budget: { max_steps: maxSteps, max_tokens: maxTokens },
      human_policy: {},
    };
    try {
      const result = await api.createCampaign(body);
      onCreated(result.campaign_id);
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "Campaign could not be started.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog title="Start an evaluation campaign" description="Run the configured attack, verification, and defense workflow against the simulated custom SUT." onClose={onClose}>
      <form className="campaign-form" onSubmit={submit}>
        <div className="form-environment">
          <div className="form-environment-icon"><ShieldCheck size={17} aria-hidden="true" /></div>
          <div><strong>Custom SUT</strong><span>Mock search, in-memory files, and message log</span></div>
          <span className="environment-tag">SIMULATED</span>
        </div>
        <div className="form-grid">
          <label className="field">
            <span>Maximum attack steps</span>
            <input type="number" min={1} max={500} required value={maxSteps} onChange={(event) => setMaxSteps(Number(event.target.value))} />
            <small>Bounds attack execution and retests.</small>
          </label>
          <label className="field">
            <span>Token budget</span>
            <input type="number" min={1} max={10000000} required value={maxTokens} onChange={(event) => setMaxTokens(Number(event.target.value))} />
            <small>Sent with the request; the current backend does not report token usage.</small>
          </label>
        </div>
        <div className="form-note"><span>Attack families</span><strong>Direct injection · Indirect injection · Goal hijacking</strong><small>The request includes these family labels; generation follows the backend’s built-in rotation.</small></div>
        {error && <div className="inline-error" role="alert">{error}</div>}
        <div className="dialog-actions">
          <Button variant="quiet" onClick={onClose} disabled={submitting}>Cancel</Button>
          <Button variant="primary" type="submit" disabled={submitting || maxSteps < 1 || maxTokens < 1}>
            {submitting ? <><LoaderCircle size={16} className="spin-subtle" /> Starting</> : <>Start campaign <ArrowRight size={15} /></>}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
