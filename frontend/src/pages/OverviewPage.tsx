import { useCallback, useEffect, useState } from "react";
import { ArrowRight, Clock3, Plus, ShieldAlert } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import type { CampaignPage, MetricsResponse } from "../types";
import CreateCampaignDialog from "../components/CreateCampaignDialog";
import { Button, EmptyBlock, ErrorBlock, formatDate, formatPercent, LoadingBlock, Metric, PageHeader, SectionHeading, StatusBadge } from "../components/ui";

export default function OverviewPage() {
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [campaigns, setCampaigns] = useState<CampaignPage | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const navigate = useNavigate();

  const load = useCallback(async (signal?: AbortSignal) => {
    setError("");
    try {
      const [nextMetrics, nextCampaigns] = await Promise.all([api.metrics(signal), api.campaigns(1, 6, signal)]);
      setMetrics(nextMetrics);
      setCampaigns(nextCampaigns);
    } catch (reason) {
      if (!signal?.aborted) setError(reason instanceof Error ? reason.message : "Workspace data could not be loaded.");
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    const timer = window.setInterval(() => { void load(); }, 30000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [load]);

  const handleCreated = (id: string) => navigate(`/campaigns/${encodeURIComponent(id)}`);
  const noCampaigns = campaigns?.total === 0;

  return (
    <>
      <PageHeader
        eyebrow="RELIABILITY WORKSPACE"
        title="Overview"
        description="A current view of agent security evaluations and campaign outcomes."
        actions={<Button variant="primary" onClick={() => setShowCreate(true)}><Plus size={16} /> New campaign</Button>}
      />

      {error && <ErrorBlock title="Workspace data unavailable" message={error} onRetry={() => { setLoading(true); void load(); }} />}

      {loading && !metrics ? <LoadingBlock label="Connecting to the evaluation API" /> : metrics && (
        <>
          <section className="metric-band" aria-label="Workspace metrics">
            <Metric label="Campaigns" value={String(metrics.total_campaigns)} detail={`${metrics.completed_campaigns} completed`} />
            <Metric
              label="Mean attack success rate"
              value={metrics.total_campaigns ? formatPercent(metrics.average_asr_after) : "—"}
              detail={metrics.total_campaigns ? `Before ${formatPercent(metrics.average_asr_before)} · after ${formatPercent(metrics.average_asr_after)}` : "No campaign measurements"}
              tone={metrics.total_campaigns > 0 && metrics.average_asr_after < metrics.average_asr_before ? "good" : "default"}
            />
            <Metric label="Regression tests" value={String(metrics.total_regression_tests)} detail="Across all campaigns" />
            <Metric label="Applied patches" value={String(metrics.total_patches_applied)} detail="Recorded by the API" />
          </section>

          <section className="overview-section">
            <SectionHeading
              title="Recent campaigns"
              description="Latest campaigns returned by the API."
              action={<Link className="text-link" to="/campaigns">All campaigns <ArrowRight size={14} /></Link>}
            />
            {campaigns?.campaigns.length ? (
              <div className="table-frame">
                <table className="data-table" aria-label="Recent campaigns">
                  <thead><tr><th scope="col">Campaign</th><th scope="col">Status</th><th scope="col">Phase</th><th scope="col">Attack success rate</th><th scope="col">Updated</th><th scope="col"><span className="visually-hidden">Open</span></th></tr></thead>
                  <tbody>
                    {campaigns.campaigns.map((campaign) => (
                      <tr key={campaign.campaign_id}>
                        <td><Link className="mono campaign-id-link" to={`/campaigns/${encodeURIComponent(campaign.campaign_id)}`}>{campaign.campaign_id}</Link><span className="cell-subtext">Created {formatDate(campaign.created_at, false)}</span></td>
                        <td><StatusBadge status={campaign.status} /></td>
                        <td><span className="phase-label">{campaign.phase.replaceAll("_", " ")}</span></td>
                        <td className="numeric-cell">{formatPercent(campaign.asr_after ?? campaign.asr_before)}</td>
                        <td className="muted-cell">{formatDate(campaign.updated_at ?? campaign.created_at)}</td>
                        <td><Link className="row-open" to={`/campaigns/${encodeURIComponent(campaign.campaign_id)}`} aria-label={`Open campaign ${campaign.campaign_id}`}><ArrowRight size={16} /></Link></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : noCampaigns ? (
              <EmptyBlock title="No campaigns yet" description="Start an evaluation to see attack, verification, and utility results here." action={<Button variant="primary" onClick={() => setShowCreate(true)}><Plus size={16} /> Start a campaign</Button>} />
            ) : !loading && !error ? (
              <EmptyBlock title="No recent campaigns" description="Campaign data will appear here when it becomes available." />
            ) : null}
          </section>

          <section className="overview-footnote" aria-label="Evaluation context">
            <div className="footnote-mark"><ShieldAlert size={17} aria-hidden="true" /></div>
            <div><strong>Evaluation context</strong><p>VERITAS-lite runs the custom SUT in a simulated environment. Aggregate values above come directly from the campaign metrics API.</p></div>
            <div className="footnote-meta"><Clock3 size={14} aria-hidden="true" /><span>Refreshes every 30 seconds</span></div>
          </section>
        </>
      )}

      {showCreate && <CreateCampaignDialog onClose={() => setShowCreate(false)} onCreated={handleCreated} />}
    </>
  );
}
