import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowUpRight, Ban, Check, Download, FileText, LoaderCircle, Radio, RefreshCw, Shield, ShieldAlert, ShieldCheck, SquareActivity, Trash2 } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, campaignSocketUrl } from "../api";
import type { CampaignReport, CampaignReportResponse, CampaignStatusResponse, LiveCampaignUpdate, Trace } from "../types";
import TraceExplorer from "../components/TraceExplorer";
import DeleteCampaignDialog from "../components/DeleteCampaignDialog";
import { Button, Dialog, EmptyBlock, ErrorBlock, formatDate, formatDuration, formatPercent, LoadingBlock, Metric, PageHeader, SectionHeading, StatusBadge } from "../components/ui";

type DetailTab = "evaluation" | "traces" | "report";
type StreamState = "connecting" | "connected" | "offline";

function delta(before: number, after: number, higherIsBetter = false): { label: string; tone: "good" | "caution" | "bad" | "default" } {
  const value = Math.round((after - before) * 100);
  if (value === 0) return { label: "No change", tone: "default" };
  const favorable = higherIsBetter ? value > 0 : value < 0;
  return { label: `${value > 0 ? "+" : ""}${value} pp`, tone: favorable ? "good" : "caution" };
}

function ComparisonBar({ label, before, after, lowerIsBetter }: { label: string; before: number; after: number; lowerIsBetter: boolean }) {
  const change = delta(before, after, !lowerIsBetter);
  return (
    <div className="comparison-row">
      <div className="comparison-title"><strong>{label}</strong><span className={`delta delta--${change.tone}`}>{change.label}</span></div>
      <div className="comparison-line"><span>Before</span><div className="comparison-track"><i className="comparison-fill comparison-fill--before" style={{ width: `${Math.min(100, Math.max(0, before * 100))}%` }} /></div><strong>{formatPercent(before)}</strong></div>
      <div className="comparison-line"><span>After</span><div className="comparison-track"><i className="comparison-fill comparison-fill--after" style={{ width: `${Math.min(100, Math.max(0, after * 100))}%` }} /></div><strong>{formatPercent(after)}</strong></div>
    </div>
  );
}

function LiveIndicator({ state }: { state: StreamState }) {
  return <span className={`live-indicator live-indicator--${state}`}><span className="live-dot" aria-hidden="true" />{state === "connected" ? "Live updates" : state === "connecting" ? "Connecting" : "Polling status"}</span>;
}

function ReportPanel({
  response,
  onDownload,
}: {
  response: CampaignReportResponse;
  onDownload: () => void;
}) {
  const report = response.report;
  const asrChange = delta(report.asr_before, report.asr_after);
  const utilityChange = delta(report.normal_acc_before, report.normal_acc_after, true);
  return (
    <div className="report-layout">
      <div className="report-topline">
        <div><div className="eyebrow">FINAL EVALUATION</div><h2>Campaign report</h2><p>{response.summary || report.summary}</p></div>
        <Button onClick={onDownload}><Download size={15} /> Download JSON</Button>
      </div>
      <div className="report-metric-grid">
        <div className="report-metric"><span>Attack success rate</span><div><strong>{formatPercent(report.asr_before)}</strong><ArrowUpRight size={15} aria-hidden="true" /><strong>{formatPercent(report.asr_after)}</strong></div><small className={`delta delta--${asrChange.tone}`}>{asrChange.label} · lower is better</small></div>
        <div className="report-metric"><span>Normal-task accuracy</span><div><strong>{formatPercent(report.normal_acc_before)}</strong><ArrowUpRight size={15} aria-hidden="true" /><strong>{formatPercent(report.normal_acc_after)}</strong></div><small className={`delta delta--${utilityChange.tone}`}>{utilityChange.label} · no threshold returned by API</small></div>
        <div className="report-metric"><span>Held-out ASR</span><div><strong>{formatPercent(report.asr_held_out_before)}</strong><ArrowUpRight size={15} aria-hidden="true" /><strong>{formatPercent(report.asr_held_out_after)}</strong></div><small>Before → after patch</small></div>
      </div>
      {report.asr_held_out_before === 0 && <div className="notice notice--warning"><ShieldAlert size={16} aria-hidden="true" /><span>The API reports a 0% held-out baseline. It does not distinguish a measured zero from the current default value, so treat this baseline as unverified.</span></div>}

      <div className="report-secondary-grid">
        <section className="report-section">
          <SectionHeading title="Evaluation details" />
          <dl className="report-facts">
            <div><dt>Duration</dt><dd>{formatDuration(report.duration_seconds)}</dd></div>
            <div><dt>Attack steps</dt><dd>{report.total_steps}</dd></div>
            <div><dt>Human interventions</dt><dd>{report.human_interventions}</dd></div>
            <div><dt>Regression tests added</dt><dd>{report.regression_tests_added}</dd></div>
            <div><dt>Patches applied</dt><dd>{report.patches_applied}</dd></div>
          </dl>
        </section>
        <section className="report-section">
          <SectionHeading title="Applied patch records" description="The report includes patch IDs, but not proposal details." />
          {report.patches.length ? <ul className="id-list">{report.patches.map((patch, index) => <li key={`${patch.id ?? "patch"}-${index}`}><ShieldCheck size={15} aria-hidden="true" /><code>{patch.id ?? "Patch ID unavailable"}</code><StatusBadge status="completed" label="Applied" /></li>)}</ul> : <p className="muted-paragraph">No patch record was included in this report.</p>}
        </section>
      </div>

      <section className="report-section report-violations">
        <SectionHeading title="Verifier violation summaries" description="Failure summaries returned in the final report." />
        {report.violations.length ? <div className="violation-list">{report.violations.map((violation, index) => (
          <article className="violation-item" key={`${violation.violation_type}-${index}`}>
            <div className="violation-symbol"><ShieldAlert size={16} aria-hidden="true" /></div>
            <div className="violation-main"><div><strong>{violation.violation_type.replaceAll("_", " ")}</strong><span className="violation-family">{violation.attack_family.replaceAll("_", " ")}</span></div>
              <p>Tool: <code>{violation.tool_violated}</code> · Injection vector: <code>{violation.injection_vector}</code></p>
              {!!violation.gates_fired.length && <div className="gate-chips">{violation.gates_fired.map((gate) => <span className="gate-chip" key={gate}>{gate.replaceAll("_", " ")}</span>)}</div>}
            </div>
          </article>
        ))}</div> : <div className="notice notice--success"><Check size={16} aria-hidden="true" /><span>No verifier violation summaries were included in the final report.</span></div>}
      </section>
    </div>
  );
}

export default function CampaignDetailPage() {
  const { campaignId = "" } = useParams();
  const navigate = useNavigate();
  const [campaign, setCampaign] = useState<CampaignStatusResponse | null>(null);
  const [traces, setTraces] = useState<Trace[]>([]);
  const [reportResponse, setReportResponse] = useState<CampaignReportResponse | null>(null);
  const [tab, setTab] = useState<DetailTab>("evaluation");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reportError, setReportError] = useState("");
  const [traceError, setTraceError] = useState("");
  const [stream, setStream] = useState<StreamState>("connecting");
  const [lastSignal, setLastSignal] = useState<LiveCampaignUpdate | null>(null);
  const [confirmStop, setConfirmStop] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [notice, setNotice] = useState("");
  const [actionError, setActionError] = useState("");
  const lastStep = useRef<number | null>(null);

  const loadCampaign = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await api.campaign(campaignId, signal);
      setCampaign(result);
      setError("");
    } catch (reason) {
      if (!signal?.aborted) setError(reason instanceof Error ? reason.message : "Campaign could not be loaded.");
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [campaignId]);

  const loadTraces = useCallback(async (signal?: AbortSignal) => {
    setTraceError("");
    try {
      const result = await api.traces(campaignId, signal);
      setTraces(result.traces);
    } catch (reason) {
      if (!signal?.aborted) setTraceError(reason instanceof Error ? reason.message : "Traces could not be loaded.");
    }
  }, [campaignId]);

  const loadReport = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await api.report(campaignId, signal);
      setReportResponse(result);
      setReportError("");
    } catch (reason) {
      if (!signal?.aborted) setReportError(reason instanceof Error ? reason.message : "Report is not available yet.");
    }
  }, [campaignId]);

  useEffect(() => {
    const controller = new AbortController();
    setCampaign(null);
    setTraces([]);
    setReportResponse(null);
    setLoading(true);
    setError("");
    void loadCampaign(controller.signal);
    void loadTraces(controller.signal);
    return () => controller.abort();
  }, [campaignId, loadCampaign, loadTraces]);

  useEffect(() => {
    if (!campaign || campaign.status !== "completed") return;
    const controller = new AbortController();
    void loadReport(controller.signal);
    return () => controller.abort();
  }, [campaign?.status, loadReport, campaignId]);

  useEffect(() => {
    if (!campaign || campaign.status !== "running") {
      setStream("offline");
      return;
    }
    let disposed = false;
    let socket: WebSocket | null = null;
    let statusTimer = 0;
    let traceTimer = 0;
    setStream("connecting");
    try {
      socket = new WebSocket(campaignSocketUrl(campaignId));
      socket.onopen = () => { if (!disposed) setStream("connected"); };
      socket.onmessage = (event) => {
        if (disposed) return;
        try {
          const update = JSON.parse(String(event.data)) as LiveCampaignUpdate;
          if (update.error) return;
          setLastSignal(update);
          if (update.step_count !== undefined && update.step_count !== lastStep.current) {
            lastStep.current = update.step_count;
            void loadTraces();
          }
          if (update.phase) setCampaign((current) => current ? { ...current, phase: update.phase! } : current);
        } catch {
          // Ignore malformed live messages and continue to use the status endpoint.
        }
      };
      socket.onerror = () => { if (!disposed) setStream("offline"); };
      socket.onclose = () => { if (!disposed) setStream("offline"); };
    } catch {
      setStream("offline");
    }
    statusTimer = window.setInterval(() => { void loadCampaign(); }, 5000);
    traceTimer = window.setInterval(() => { void loadTraces(); }, 15000);
    return () => {
      disposed = true;
      window.clearInterval(statusTimer);
      window.clearInterval(traceTimer);
      socket?.close();
    };
  }, [campaign?.status, campaignId, loadCampaign, loadTraces]);

  const currentAsr = campaign?.asr_after ?? campaign?.asr_before;
  const isRunning = campaign?.status === "running";
  const isPaused = campaign?.status === "paused";

  async function stopCampaign() {
    setStopping(true);
    setActionError("");
    try {
      await api.cancelCampaign(campaignId);
      setCampaign((current) => current ? { ...current, status: "cancelled" } : current);
      setNotice("Campaign cancelled.");
      setConfirmStop(false);
    } catch (reason) {
      setActionError(reason instanceof ApiError ? reason.message : "Campaign could not be cancelled.");
    } finally {
      setStopping(false);
    }
  }

  function downloadReport() {
    if (!reportResponse) return;
    const blob = new Blob([JSON.stringify(reportResponse, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `veritas-report-${campaignId}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  const displayedReport: CampaignReport | null = reportResponse?.report ?? null;
  const phase = campaign?.phase ?? lastSignal?.phase;
  const detailActions = isRunning
    ? <Button variant="danger" onClick={() => { setActionError(""); setConfirmStop(true); }}><Ban size={15} /> Stop campaign</Button>
    : <Button variant="danger" onClick={() => setConfirmDelete(true)}><Trash2 size={15} /> Delete campaign</Button>;

  if (loading && !campaign) return <LoadingBlock label="Loading campaign workspace" />;
  if (error && !campaign) return <><div className="detail-back"><Link to="/campaigns"><ArrowLeft size={15} /> Campaigns</Link></div><ErrorBlock title="Campaign unavailable" message={error} onRetry={() => { setLoading(true); void loadCampaign(); }} /></>;
  if (!campaign) return <EmptyBlock title="Campaign not found" description="The API did not return this campaign." action={<Button onClick={() => window.location.assign("/campaigns")}>Back to campaigns</Button>} />;

  return (
    <>
      <div className="detail-back"><Link to="/campaigns"><ArrowLeft size={15} /> Campaigns</Link><span>/</span><code>{campaign.campaign_id}</code></div>
      <PageHeader
        eyebrow="CAMPAIGN WORKSPACE"
        title={<span className="mono title-id">{campaign.campaign_id}</span>}
        description={`Started ${formatDate(campaign.created_at)} · ${campaign.step_count} steps recorded`}
        actions={<>{isRunning && <LiveIndicator state={stream} />}<StatusBadge status={campaign.status} />{detailActions}</>}
      />
      {notice && <div className="notice notice--success dismissible"><Check size={16} aria-hidden="true" /><span>{notice}</span><button className="icon-button" onClick={() => setNotice("")} aria-label="Dismiss message">×</button></div>}
      {actionError && <div className="inline-error action-error" role="alert">{actionError}</div>}

      <section className="campaign-current" aria-label="Current campaign phase">
        <div className="campaign-current-icon"><SquareActivity size={17} aria-hidden="true" /></div>
        <div className="campaign-current-copy"><span>Current phase</span><strong>{phase?.replaceAll("_", " ") ?? "Unknown"}</strong></div>
        <div className="campaign-current-step"><span>Steps used</span><strong>{campaign.step_count}</strong></div>
        {lastSignal && <div className="campaign-signal-time"><Radio size={14} aria-hidden="true" /><span>Live signal received</span></div>}
      </section>

      {isPaused && <div className="notice notice--warning review-notice"><Shield size={17} aria-hidden="true" /><div><strong>Campaign paused for human review</strong><p>The API does not expose the patch proposal or its details, so this workspace cannot present a reviewable approval decision.</p></div><a className="text-link" href={`${(import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/$/, "")}/docs`} target="_blank" rel="noreferrer">API docs <ArrowUpRight size={14} /></a></div>}
      {campaign.status === "failed" && <div className="notice notice--danger"><ShieldAlert size={16} aria-hidden="true" /><span>The campaign failed. The status endpoint does not include a failure reason.</span></div>}

      <div className="campaign-tabs" role="group" aria-label="Campaign sections">
        <button type="button" aria-pressed={tab === "evaluation"} onClick={() => setTab("evaluation")}>Evaluation</button>
        <button type="button" aria-pressed={tab === "traces"} onClick={() => setTab("traces")}>Traces <span className="tab-count">{traces.length}</span></button>
        <button type="button" aria-pressed={tab === "report"} onClick={() => setTab("report")} disabled={!displayedReport}>Final report</button>
      </div>

      <div className="tab-panel" key={tab}>
        {tab === "evaluation" && <>
          <div className="campaign-metrics">
            <Metric label="Attack success rate" value={formatPercent(currentAsr)} detail={campaign.asr_before == null ? "Awaiting verifier result" : `Before patch ${formatPercent(campaign.asr_before)} · current ${formatPercent(currentAsr)}`} tone={campaign.asr_after != null && campaign.asr_before != null && campaign.asr_after < campaign.asr_before ? "good" : "default"} />
            <Metric label="Normal-task accuracy" value={formatPercent(campaign.normal_acc_after ?? campaign.normal_acc_before)} detail={campaign.normal_acc_before == null ? "Awaiting baseline" : `Before ${formatPercent(campaign.normal_acc_before)} · after ${formatPercent(campaign.normal_acc_after)}`} />
            <Metric label="Traces recorded" value={String(traces.length)} detail="Campaign-scoped trace endpoint" />
            <Metric label="Current phase" value={phase?.replaceAll("_", " ") ?? "—"} detail={isRunning ? "Campaign is running" : `Status: ${campaign.status}`} />
          </div>

          {displayedReport ? <>
            <div className="evaluation-comparisons">
              <SectionHeading title="Before and after" description="Values from the completed campaign report." />
              <div className="comparison-grid">
                <ComparisonBar label="Attack success rate" before={displayedReport.asr_before} after={displayedReport.asr_after} lowerIsBetter />
                <ComparisonBar label="Normal-task accuracy" before={displayedReport.normal_acc_before} after={displayedReport.normal_acc_after} lowerIsBetter={false} />
              </div>
            </div>
            <div className="detail-summary-grid">
              <section className="summary-panel">
                <div className="summary-icon summary-icon--security"><ShieldCheck size={17} aria-hidden="true" /></div>
                <div><span>Held-out evaluation</span><strong>{formatPercent(displayedReport.asr_held_out_after)} ASR after patch</strong><p>Reported baseline {formatPercent(displayedReport.asr_held_out_before)} · baseline measurement may be unavailable.</p></div>
              </section>
              <section className="summary-panel">
                <div className="summary-icon"><FileText size={17} aria-hidden="true" /></div>
                <div><span>Regression outcome</span><strong>{displayedReport.regression_tests_added} tests added</strong><p>Count returned by the campaign report; individual regression records are not exposed by this API.</p></div>
              </section>
            </div>
          </> : <div className="evaluation-waiting"><div className="evaluation-waiting-icon">{isRunning ? <LoaderCircle size={19} className="spin-subtle" /> : <FileText size={18} />}</div><div><strong>{isRunning ? "Evaluation in progress" : campaign.status === "completed" ? "Report is not available" : "No final report yet"}</strong><p>{isRunning ? "The workspace reflects the latest phase and metrics received from the API." : reportError || "A final report is returned when the campaign completes."}</p></div><Button size="sm" onClick={() => { void loadCampaign(); void loadTraces(); if (campaign.status === "completed") void loadReport(); }}><RefreshCw size={14} /> Refresh</Button></div>}

          {displayedReport && <section className="report-quick-facts"><SectionHeading title="Campaign summary" action={<button className="text-link" onClick={() => setTab("report")}>Open report <ArrowUpRight size={14} /></button>} /><p>{reportResponse?.summary || displayedReport.summary}</p><div className="quick-facts-line"><span>{formatDuration(displayedReport.duration_seconds)}</span><span>{displayedReport.total_steps} steps</span><span>{displayedReport.patches_applied} patches</span><span>{displayedReport.human_interventions} human reviews</span></div></section>}
        </>}
        {tab === "traces" && <section className="trace-section"><SectionHeading title="Execution traces" description="Tool calls and responses recorded for this campaign. Select a trace to inspect its details." action={<Button size="sm" onClick={() => void loadTraces()}><RefreshCw size={14} /> Refresh traces</Button>} />{traceError ? <ErrorBlock title="Traces unavailable" message={traceError} onRetry={() => { void loadTraces(); }} /> : <TraceExplorer traces={traces} />}</section>}
        {tab === "report" && (displayedReport ? <ReportPanel response={reportResponse!} onDownload={downloadReport} /> : <EmptyBlock title="Report not ready" description={reportError || "The API serves a final report after campaign completion."} />)}
      </div>

      {confirmStop && <Dialog title="Stop this campaign?" description="The campaign worker will be cancelled and its status will be recorded as cancelled." onClose={() => setConfirmStop(false)}>
        <div className="confirm-copy"><p>Campaign <code>{campaign.campaign_id}</code> is running. Stopping it ends the current evaluation.</p>{actionError && <div className="inline-error" role="alert">{actionError}</div>}</div>
        <div className="dialog-actions"><Button variant="quiet" onClick={() => setConfirmStop(false)} disabled={stopping}>Keep running</Button><Button variant="danger" onClick={() => void stopCampaign()} disabled={stopping}>{stopping ? <><LoaderCircle size={15} className="spin-subtle" /> Stopping</> : "Stop campaign"}</Button></div>
      </Dialog>}
      {confirmDelete && <DeleteCampaignDialog campaignId={campaign.campaign_id} onClose={() => setConfirmDelete(false)} onDeleted={() => navigate("/campaigns", { replace: true })} />}
    </>
  );
}
