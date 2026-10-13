import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar.jsx';
import Footer from './components/Footer.jsx';
import IncidentQueue from './pages/IncidentQueue.jsx';
import IncidentDetail from './pages/IncidentDetail.jsx';
import AuditLog from './pages/AuditLog.jsx';
import Alerts from './pages/Alerts.jsx';
import ChatPanel from './pages/ChatPanel.jsx';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <Sidebar />
        <div className="main-content">
          <div className="content-wrapper">
            <Routes>
              <Route path="/" element={<IncidentQueue />} />
              <Route path="/incidents/:id" element={<IncidentDetail />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/diagnose" element={<ChatPanel />} />
              <Route path="/audit" element={<AuditLog />} />
            </Routes>
          </div>
          <Footer />
        </div>
      </div>
    </BrowserRouter>
  );
}
