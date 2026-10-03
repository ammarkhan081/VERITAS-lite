import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, FileSearch, Search } from "lucide-react";
import type { Trace } from "../types";
import { Button, Drawer, EmptyBlock, formatDate, labelize, StatusBadge } from "./ui";

const PAGE_SIZE = 25;

function json(value: unknown): string {
  return JSON.stringify(value ?? {}, null, 2);
}

function TraceDetails({ trace, onClose }: { trace: Trace; onClose: () => void }) {
  return (
    <Drawer
      title="Trace details"
      description={`${trace.phase.replaceAll("_", " ")} · ${trace.id}`}
      onClose={onClose}
    >
      <div className="trace-detail-intro">
        <StatusBadge status={trace.phase} />
        <span className="mono trace-detail-id">{trace.id}</span>
      </div>
      <section className="detail-section">
        <h3>Task</h3>
        <p className="detail-prose">{trace.task || "No task recorded."}</p>
        <div className="detail-meta-grid">
          <div><span>Attack ID</span><code>{trace.attack_id ?? "Normal task"}</code></div>
          <div><span>Recorded</span><strong>{formatDate(trace.created_at)}</strong></div>
          <div><span>Tool calls</span><strong>{trace.tool_calls.length}</strong></div>
          <div><span>Verifier decisions</span><strong>{trace.gates_fired.length || "Not attached"}</strong></div>
        </div>
      </section>

      <section className="detail-section">
        <h3>Tool activity <span className="section-count">{trace.tool_calls.length}</span></h3>
        {trace.tool_calls.length ? <div className="tool-call-list">
          {trace.tool_calls.map((call, index) => (
            <details className="tool-call" key={`${call.call_index}-${index}`}>
              <summary><span className="tool-call-index">{String(call.call_index + 1).padStart(2, "0")}</span><code>{call.name}</code><span className="tool-call-time">{formatDate(call.timestamp)}</span></summary>
              <div className="tool-call-content">
                <h4>Arguments</h4><pre>{json(call.args)}</pre>
                {call.result && <><h4>Result</h4><pre>{json(call.result)}</pre></>}
                {call.error && <><h4>Error</h4><pre className="error-pre">{call.error}</pre></>}
              </div>
            </details>
          ))}
        </div> : <p className="muted-paragraph">No tool calls were recorded for this trace.</p>}
      </section>

      <section className="detail-section">
        <h3>Gate decisions <span className="section-count">{trace.gates_fired.length}</span></h3>
        {trace.gates_fired.length ? (
          <div className="gate-list">
            {trace.gates_fired.map((gate, index) => (
              <details className={`gate-row ${gate.passed ? "gate-row--passed" : "gate-row--failed"}`} key={`${gate.gate}-${index}`}>
                <summary><StatusBadge status={gate.passed ? "passed" : "failed"} /><code>{labelize(gate.gate)}</code></summary>
                {Object.keys(gate.evidence ?? {}).length > 0 && <pre>{json(gate.evidence)}</pre>}
              </details>
            ))}
          </div>
        ) : <div className="notice notice--neutral compact-notice"><FileSearch size={15} aria-hidden="true" /><span>This stored trace does not include gate decisions. Campaign reports may include a separate violation summary.</span></div>}
      </section>

      <section className="detail-section">
        <h3>Final response</h3>
        <pre className="response-pre">{trace.final_response || "No final response recorded."}</pre>
      </section>

      <details className="raw-disclosure">
        <summary>Raw trace payload</summary>
        <pre>{json(trace)}</pre>
      </details>
    </Drawer>
  );
}

export default function TraceExplorer({ traces }: { traces: Trace[] }) {
  const [query, setQuery] = useState("");
  const [phase, setPhase] = useState("all");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Trace | null>(null);

  const phases = useMemo(() => Array.from(new Set(traces.map((trace) => trace.phase))).sort(), [traces]);
  const filtered = useMemo(() => traces.filter((trace) => {
    const needle = query.trim().toLowerCase();
    const matchesQuery = !needle || [trace.id, trace.attack_id, trace.task, ...trace.tool_calls.map((call) => call.name)]
      .some((value) => String(value ?? "").toLowerCase().includes(needle));
    return matchesQuery && (phase === "all" || trace.phase === phase);
  }), [traces, query, phase]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const visible = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  function updateQuery(value: string) { setQuery(value); setPage(1); }
  function updatePhase(value: string) { setPhase(value); setPage(1); }

  if (!traces.length) return <EmptyBlock title="No traces recorded" description="Execution traces will appear here after campaign tasks and attacks run." />;

  return (
    <>
      <div className="trace-toolbar">
        <label className="search-field trace-search"><Search size={16} aria-hidden="true" /><span className="visually-hidden">Search traces</span><input value={query} onChange={(event) => updateQuery(event.target.value)} placeholder="Search trace, task, or tool" /></label>
        <label className="select-field"><span className="visually-hidden">Filter traces by phase</span><select value={phase} onChange={(event) => updatePhase(event.target.value)}><option value="all">All phases</option>{phases.map((item) => <option key={item} value={item}>{labelize(item)}</option>)}</select></label>
        <span className="toolbar-count">{filtered.length} {filtered.length === 1 ? "trace" : "traces"}</span>
      </div>
      {visible.length ? <>
        <div className="table-frame trace-table-frame">
          <table className="data-table" aria-label="Campaign execution traces">
            <thead><tr><th scope="col">Trace</th><th scope="col">Phase</th><th scope="col">Task / attack</th><th scope="col">Tools</th><th scope="col">Gate data</th><th scope="col">Recorded</th></tr></thead>
            <tbody>{visible.map((trace) => {
              const failedCount = trace.gates_fired.filter((gate) => !gate.passed).length;
              return <tr key={trace.id} className="trace-table-row">
                <td><button className="table-primary-link mono" onClick={() => setSelected(trace)}>{trace.id}</button><span className="cell-subtext">{trace.attack_id ? "Attack trace" : "Normal task"}</span></td>
                <td><StatusBadge status={trace.phase} /></td>
                <td className="task-cell"><span title={trace.task}>{trace.task || "—"}</span>{trace.attack_id && <code className="cell-subtext mono">{trace.attack_id}</code>}</td>
                <td className="numeric-cell">{trace.tool_calls.length}</td>
                <td>{trace.gates_fired.length ? <StatusBadge status={failedCount ? "failed" : "passed"} label={failedCount ? `${failedCount} failed` : "All passed"} /> : <span className="muted-cell">Not attached</span>}</td>
                <td className="muted-cell">{formatDate(trace.created_at)}</td>
              </tr>;
            })}</tbody>
          </table>
        </div>
        {filtered.length > PAGE_SIZE && <div className="pagination"><span>Page {page} of {pageCount}</span><div><Button size="sm" onClick={() => setPage((current) => Math.max(1, current - 1))} disabled={page <= 1}><ChevronLeft size={14} /> Previous</Button><Button size="sm" onClick={() => setPage((current) => Math.min(pageCount, current + 1))} disabled={page >= pageCount}>Next <ChevronRight size={14} /></Button></div></div>}
      </> : <EmptyBlock title="No matching traces" description="Try another search or choose a different phase." />}
      {selected && <TraceDetails trace={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
