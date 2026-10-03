import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, Plus, Search, Trash2 } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import type { CampaignPage } from "../types";
import CreateCampaignDialog from "../components/CreateCampaignDialog";
import DeleteCampaignDialog from "../components/DeleteCampaignDialog";
import { Button, EmptyBlock, ErrorBlock, formatDate, formatPercent, LoadingBlock, PageHeader, StatusBadge } from "../components/ui";

const PAGE_SIZE = 20;

export default function CampaignsPage() {
  const [data, setData] = useState<CampaignPage | null>(null);
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [deleteCampaignId, setDeleteCampaignId] = useState<string | null>(null);
  const navigate = useNavigate();

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError("");
    try {
      setData(await api.campaigns(page, PAGE_SIZE, signal));
    } catch (reason) {
      if (!signal?.aborted) setError(reason instanceof Error ? reason.message : "Campaigns could not be loaded.");
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const filtered = useMemo(() => (data?.campaigns ?? []).filter((campaign) => {
    const matchesQuery = !query || campaign.campaign_id.toLowerCase().includes(query.toLowerCase());
    const matchesStatus = statusFilter === "all" || campaign.status === statusFilter;
    return matchesQuery && matchesStatus;
  }), [data, query, statusFilter]);

  return (
    <>
      <PageHeader
        eyebrow="EVALUATION HISTORY"
        title="Campaigns"
        description="Create, monitor, and inspect evaluation runs."
        actions={<Button variant="primary" onClick={() => setShowCreate(true)}><Plus size={16} /> New campaign</Button>}
      />

      <div className="list-toolbar">
        <label className="search-field">
          <Search size={16} aria-hidden="true" />
          <span className="visually-hidden">Search campaign IDs on this page</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search campaign IDs" />
        </label>
        <label className="select-field"><span className="visually-hidden">Filter by status on this page</span>
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="all">All statuses</option><option value="running">Running</option><option value="paused">Paused</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="cancelled">Cancelled</option>
          </select>
        </label>
        <span className="toolbar-count">{data ? `${data.total} total` : ""}</span>
      </div>

      {error && <ErrorBlock title="Campaigns unavailable" message={error} onRetry={() => { void load(); }} />}
      {loading && !data ? <LoadingBlock label="Loading campaigns" /> : data && (
        filtered.length ? <>
          <div className="table-frame campaign-table-frame">
            <table className="data-table" aria-label="Campaign history">
              <thead><tr><th scope="col">Campaign</th><th scope="col">Status</th><th scope="col">Current phase</th><th scope="col">Attack success rate</th><th scope="col">Normal accuracy</th><th scope="col">Started</th><th scope="col">Actions</th></tr></thead>
              <tbody>{filtered.map((campaign) => (
                <tr key={campaign.campaign_id}>
                  <td><Link className="mono campaign-id-link" to={`/campaigns/${encodeURIComponent(campaign.campaign_id)}`}>{campaign.campaign_id}</Link><span className="cell-subtext">{campaign.step_count} attack steps</span></td>
                  <td><StatusBadge status={campaign.status} /></td>
                  <td><span className="phase-label">{campaign.phase.replaceAll("_", " ")}</span></td>
                  <td className="numeric-cell">{formatPercent(campaign.asr_after ?? campaign.asr_before)}</td>
                  <td className="numeric-cell">{formatPercent(campaign.normal_acc_after ?? campaign.normal_acc_before)}</td>
                  <td className="muted-cell">{formatDate(campaign.created_at)}</td>
                  <td><div className="campaign-row-actions">
                    <Link className="row-open" to={`/campaigns/${encodeURIComponent(campaign.campaign_id)}`} aria-label={`Open campaign ${campaign.campaign_id}`} title="Open campaign"><ArrowRight size={16} /></Link>
                    <button
                      type="button"
                      className="row-delete"
                      aria-label={`Delete campaign ${campaign.campaign_id}`}
                      title={campaign.status === "running" ? "Stop the running campaign before deleting it" : "Delete campaign"}
                      disabled={campaign.status === "running"}
                      onClick={() => setDeleteCampaignId(campaign.campaign_id)}
                    ><Trash2 size={15} /></button>
                  </div></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="pagination" aria-label="Campaign pages">
            <span>Page {data.page} of {Math.max(1, Math.ceil(data.total / PAGE_SIZE))}</span>
            <div><Button size="sm" onClick={() => setPage((current) => Math.max(1, current - 1))} disabled={data.page <= 1}><ArrowLeft size={14} /> Previous</Button>
              <Button size="sm" onClick={() => setPage((current) => current + 1)} disabled={data.page * PAGE_SIZE >= data.total}>Next <ArrowRight size={14} /></Button></div>
          </div>
        </> : !loading && (
          <EmptyBlock
            title={data.total === 0 ? "No campaigns yet" : "No matches on this page"}
            description={data.total === 0 ? "Start an evaluation campaign to populate the workspace." : "Adjust the search or status filter to see other campaigns."}
            action={data.total === 0 ? <Button variant="primary" onClick={() => setShowCreate(true)}><Plus size={16} /> Start a campaign</Button> : undefined}
          />
        )
      )}

      {showCreate && <CreateCampaignDialog onClose={() => setShowCreate(false)} onCreated={(id) => navigate(`/campaigns/${encodeURIComponent(id)}`)} />}
      {deleteCampaignId && <DeleteCampaignDialog campaignId={deleteCampaignId} onClose={() => setDeleteCampaignId(null)} onDeleted={() => {
        setDeleteCampaignId(null);
        if (data?.campaigns.length === 1 && page > 1) setPage((current) => current - 1);
        else void load();
      }} />}
    </>
  );
}
