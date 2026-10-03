import { ArrowLeft } from "lucide-react";
import { Link, Route, Routes } from "react-router-dom";
import Shell from "./components/Shell";
import { PageHeader } from "./components/ui";
import CampaignDetailPage from "./pages/CampaignDetailPage";
import CampaignsPage from "./pages/CampaignsPage";
import OverviewPage from "./pages/OverviewPage";

function NotFound() {
  return <div className="not-found"><PageHeader eyebrow="404 · NOT FOUND" title="This page isn’t in the workspace" description="VERITAS-lite exposes campaign history, campaign details, traces, and reports." /><Link className="button button--secondary button--md" to="/campaigns"><ArrowLeft size={15} /> Back to campaigns</Link></div>;
}

export default function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<OverviewPage />} />
        <Route path="campaigns" element={<CampaignsPage />} />
        <Route path="campaigns/:campaignId" element={<CampaignDetailPage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
