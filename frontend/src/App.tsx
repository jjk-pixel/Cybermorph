import { useEffect, useMemo, useState } from "react";
import "./index.css";

import { NetworkScene } from "./components/network/NetworkScene";
import type { NetworkNodeData } from "./components/network/NetworkNode";

const API_BASE = "http://192.168.43.135:8000";

type ApiAsset = {
  id: number;
  name: string;
  hostname: string | null;
  ip_address: string;
  mac_address: string | null;
  vendor: string | null;
  asset_type: string;
  os_detected: string | null;
  open_ports: string;
  services: string;
  status: string;
  risk_score: number;
};

type ApiConnection = {
  id: number;
  source_asset_id: number;
  destination_asset_id: number;
  protocol: string;
  port: number | null;
  connection_type: string;
  status: string;
};

type ApiAlert = {
  id?: number;
  source_ip?: string | null;
  destination_ip?: string | null;
  protocol?: string | null;
  priority?: number | null;
  message?: string | null;
  occurrence_count?: number;
  first_seen?: string | null;
  last_seen?: string | null;
};

type ApiIncident = {
  id: number;
  status?: string;
};

type NavigationItem = {
  icon: string;
  label: string;
};

const navigation: NavigationItem[] = [
  { icon: "◉", label: "Vue 3D" },
  { icon: "◇", label: "Topologie" },
  { icon: "⚠", label: "Alertes" },
  { icon: "◈", label: "Incidents" },
  { icon: "◎", label: "Attack Graph" },
  { icon: "⬡", label: "MITRE ATT&CK" },
  { icon: "◷", label: "Timeline" },
  { icon: "◌", label: "Simulations" },
];

function App() {
  const [selectedAsset, setSelectedAsset] =
    useState<NetworkNodeData | null>(null);

  const [activeView, setActiveView] = useState("Vue 3D");
  const [cameraResetKey, setCameraResetKey] = useState(0);

  const [assets, setAssets] = useState<ApiAsset[]>([]);
  const [connections, setConnections] = useState<ApiConnection[]>([]);
  const [alerts, setAlerts] = useState<ApiAlert[]>([]);
  const [incidents, setIncidents] = useState<ApiIncident[]>([]);

  const [backendOnline, setBackendOnline] = useState(false);

  /*
   * ---------------------------------------------------------
   * Chargement des données réelles du backend
   * ---------------------------------------------------------
   */

  useEffect(() => {
    let cancelled = false;

    async function loadBackendData() {
      try {
        const [
          assetsResponse,
          connectionsResponse,
          alertsResponse,
          incidentsResponse,
        ] = await Promise.all([
          fetch(`${API_BASE}/api/assets/`),
          fetch(`${API_BASE}/api/connections/`),
          fetch(`${API_BASE}/api/alerts/`),
          fetch(`${API_BASE}/api/incidents/`).catch(() => null),
        ]);

        if (!assetsResponse.ok || !connectionsResponse.ok) {
          throw new Error("Backend API unavailable");
        }

        const assetsData = (await assetsResponse.json()) as ApiAsset[];
        const connectionsData =
          (await connectionsResponse.json()) as ApiConnection[];

        let alertsData: ApiAlert[] = [];

        if (alertsResponse.ok) {
          alertsData = (await alertsResponse.json()) as ApiAlert[];
        }

        let incidentsData: ApiIncident[] = [];

        if (incidentsResponse?.ok) {
          incidentsData = (await incidentsResponse.json()) as ApiIncident[];
        }

        if (cancelled) {
          return;
        }

        setAssets(assetsData);
        setConnections(connectionsData);
        setAlerts(alertsData);
        setIncidents(incidentsData);
        setBackendOnline(true);
      } catch (error) {
        if (!cancelled) {
          console.error(
            "[CYBERMORPH] Impossible de récupérer les données backend:",
            error
          );

          setBackendOnline(false);
        }
      }
    }

    loadBackendData();

    /*
     * Actualisation périodique.
     *
     * Le réseau est vivant : on veut que les statistiques
     * puissent évoluer sans recharger la page.
     */
    const interval = window.setInterval(loadBackendData, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  /*
   * ---------------------------------------------------------
   * Statistiques réseau
   * ---------------------------------------------------------
   */

  const activeIncidents = useMemo(() => {
    return incidents.filter((incident) => {
      const status = incident.status?.toLowerCase();

      return (
        status === "active" ||
        status === "open" ||
        status === "detected" ||
        status === "investigating"
      );
    }).length;
  }, [incidents]);

  const networkRisk = useMemo(() => {
    if (assets.length === 0) {
      return {
        label: "UNKNOWN",
        score: 0,
      };
    }

    const total = assets.reduce(
      (sum, asset) => sum + Number(asset.risk_score || 0),
      0
    );

    const average = total / assets.length;

    if (average >= 75) {
      return {
        label: "CRITICAL",
        score: average,
      };
    }

    if (average >= 50) {
      return {
        label: "HIGH",
        score: average,
      };
    }

    if (average >= 25) {
      return {
        label: "MODERATE",
        score: average,
      };
    }

    return {
      label: "LOW",
      score: average,
    };
  }, [assets]);

  /*
   * ---------------------------------------------------------
   * Sélection d'un asset
   * ---------------------------------------------------------
   */

const handleSelectAsset = (
  asset: NetworkNodeData | null
) => {
    setSelectedAsset(asset);
  };

  const clearSelection = () => {
    setSelectedAsset(null);
  };

  /*
   * ---------------------------------------------------------
   * Navigation
   * ---------------------------------------------------------
   */

  const handleNavigation = (label: string) => {
    setActiveView(label);

    /*
     * Pour l'instant la Vue 3D est notre écran principal.
     *
     * Les autres vues seront connectées progressivement aux
     * pages/components correspondants.
     */
    if (label !== "Vue 3D") {
      console.log(`[CYBERMORPH] Vue sélectionnée : ${label}`);
    }
  };

  return (
    <div className="app-shell">

      {/* =====================================================
          SIDEBAR
      ===================================================== */}

      <aside className="sidebar">

        <div className="brand">

          <div className="brand-mark">
            C
          </div>

          <div className="brand-text">

            <div className="brand-name">
              CYBERMORPH
            </div>

            <div className="brand-subtitle">
              SECURITY DIGITAL TWIN
            </div>

          </div>

        </div>

        <div className="nav-section-title">
          MONITORING
        </div>

        <nav className="navigation">

          {navigation.map((item) => {

            const isActive =
              activeView === item.label;

            return (
              <button
                key={item.label}
                className={`nav-item ${
                  isActive ? "active" : ""
                }`}
                onClick={() =>
                  handleNavigation(item.label)
                }
              >

                <span className="nav-icon">
                  {item.icon}
                </span>

                <span>
                  {item.label}
                </span>

              </button>
            );
          })}

        </nav>

        <div className="sidebar-bottom">

          <div className="system-status">

            <span
              className={`status-dot ${
                backendOnline ? "online" : "offline"
              }`}
            />

            <div>

              <div className="status-title">
                {backendOnline
                  ? "SYSTEM ONLINE"
                  : "BACKEND OFFLINE"}
              </div>

              <div className="status-subtitle">
                {backendOnline
                  ? "LIVE TELEMETRY"
                  : "CHECK API :8000"}
              </div>

            </div>

          </div>

          <div className="version">
            CYBERMORPH v1.0
          </div>

        </div>

      </aside>


      {/* =====================================================
          MAIN AREA
      ===================================================== */}

      <main className="main-area">

        {/* ===================================================
            TOP BAR
        =================================================== */}

        <header className="topbar">

          <div>

            <div className="page-label">
              SECURITY DIGITAL TWIN
            </div>

            <h1>
              Network Overview
            </h1>

          </div>

          <div className="topbar-right">

            <div className="live-indicator">

              <span
                className={
                  backendOnline
                    ? "live-dot"
                    : "live-dot offline"
                }
              />

              {backendOnline
                ? "LIVE"
                : "OFFLINE"}

            </div>

            <div className="time">
              REAL-TIME MONITORING
            </div>

          </div>

        </header>


        {/* ===================================================
            WORKSPACE
        =================================================== */}

        <section className="workspace">


          {/* =================================================
              3D NETWORK
          ================================================= */}

          <div className="network-container">

            <div className="network-header">

              <div>

                <span className="panel-label">
                  NETWORK VISUALIZATION
                </span>

                <div className="network-title">
                  LIVE TOPOLOGY
                </div>

              </div>

              <div className="network-controls">

<button
  type="button"
  onClick={() =>
    setCameraResetKey((value) => value + 1)
  }
>
  RESET VIEW
</button>
                <button
                  type="button"
                  onClick={() =>
                    console.log(
                      "[CYBERMORPH] 2D / 3D toggle"
                    )
                  }
                >
                  2D / 3D
                </button>

              </div>

            </div>


            <div className="network-placeholder">

              <NetworkScene
                onSelectAsset={handleSelectAsset}
		 resetCameraKey={cameraResetKey}
              />

            </div>

          </div>


          {/* =================================================
              RIGHT ASSET INTELLIGENCE PANEL
          ================================================= */}

          <aside className="incident-panel">

<div className="panel-header">

  <div>
    <div className="panel-label">
      ASSET INTELLIGENCE
    </div>

    <h2>
      {selectedAsset
        ? selectedAsset.ip
        : "Network Status"}
    </h2>
  </div>

  {selectedAsset && (
    <button
      type="button"
      className="close-panel-btn"
      onClick={clearSelection}
      title="Fermer"
    >
      ×
    </button>
  )}

  <div
    className={`status-badge ${
      selectedAsset?.status === "up"
        ? "online"
        : selectedAsset
        ? "offline"
        : ""
    }`}
  >
    {selectedAsset
      ? selectedAsset.status?.toUpperCase()
      : "CLEAR"}
  </div>

</div>

            {/* =================================================
                ASSET SELECTION
            ================================================= */}

            {selectedAsset ? (

              <div className="asset-details">

                {/* Asset title */}

                <div className="asset-heading">


                  <div>


                    <div className="asset-heading-subtitle">
                      {selectedAsset.hostname ||
                        "HOSTNAME UNKNOWN"}
                    </div>

                  </div>

                </div>


                {/* Type */}

                <div className="asset-type">
                  {selectedAsset.type?.toUpperCase() ||
                    "UNKNOWN ASSET"}
                </div>


                {/* Risk */}

                <div className="asset-risk">

                  <span>
                    RISK SCORE
                  </span>

                  <strong>
                    {Number(
                      selectedAsset.risk_score ?? 0
                    ).toFixed(1)}
                  </strong>

                </div>


                {/* Status */}

                <div className="detail-row">

                  <span>
                    STATUS
                  </span>

                  <strong
                    className={
                      selectedAsset.status === "up"
                        ? "detail-online"
                        : "detail-offline"
                    }
                  >
                    {selectedAsset.status?.toUpperCase() ||
                      "UNKNOWN"}
                  </strong>

                </div>


                {/* IP */}

                <div className="detail-row">

                  <span>
                    IP ADDRESS
                  </span>

                  <strong>
                    {selectedAsset.ip}
                  </strong>

                </div>


                {/* Hostname */}

                <div className="detail-row">

                  <span>
                    HOSTNAME
                  </span>

                  <strong>
                    {selectedAsset.hostname || "—"}
                  </strong>

                </div>


                {/* Vendor */}

                <div className="detail-row">

                  <span>
                    VENDOR
                  </span>

                  <strong>
                    {selectedAsset.vendor || "—"}
                  </strong>

                </div>


                {/* OS */}

                <div className="detail-row">

                  <span>
                    OPERATING SYSTEM
                  </span>

                  <strong>
                    {selectedAsset.os_detected ||
                      "Unknown"}
                  </strong>

                </div>


                {/* Ports */}

                <div className="detail-row">

                  <span>
                    OPEN PORTS
                  </span>

                  <strong>
                    {selectedAsset.open_ports || "—"}
                  </strong>

                </div>


                {/* Services */}

                <div className="detail-row">

                  <span>
                    SERVICES
                  </span>

                  <strong>
                    {selectedAsset.services || "—"}
                  </strong>

                </div>


              </div>

            ) : (

              /* =================================================
                 NO ASSET SELECTED
              ================================================= */

              <div className="empty-incident">

                <div className="empty-icon">
                  ✓
                </div>

                <div className="empty-title">
                  Network Monitoring
                </div>

                <div className="empty-description">
                  Select an asset in the 3D network
                  to inspect its security state,
                  services, exposure and risk.
                </div>

                <div className="empty-network-state">

                  <div>
                    <span>ASSETS</span>
                    <strong>
                      {assets.length
                        .toString()
                        .padStart(2, "0")}
                    </strong>
                  </div>

                  <div>
                    <span>CONNECTIONS</span>
                    <strong>
                      {connections.length
                        .toString()
                        .padStart(2, "0")}
                    </strong>
                  </div>

                  <div>
                    <span>ALERTS</span>
                    <strong>
                      {alerts.length
                        .toString()
                        .padStart(2, "0")}
                    </strong>
                  </div>

                </div>

              </div>

            )}

          </aside>

        </section>


        {/* ===================================================
            BOTTOM METRICS
        =================================================== */}

        <footer className="metrics-bar">


          <div className="metric">

            <span className="metric-label">
              ASSETS
            </span>

            <strong>
              {assets.length
                .toString()
                .padStart(2, "0")}
            </strong>

          </div>


          <div className="metric">

            <span className="metric-label">
              CONNECTIONS
            </span>

            <strong>
              {connections.length
                .toString()
                .padStart(2, "0")}
            </strong>

          </div>


          <div className="metric">

            <span className="metric-label">
              ALERTS
            </span>

            <strong>
              {alerts.length
                .toString()
                .padStart(2, "0")}
            </strong>

          </div>


          <div className="metric">

            <span className="metric-label">
              ACTIVE INCIDENTS
            </span>

            <strong>
              {activeIncidents
                .toString()
                .padStart(2, "0")}
            </strong>

          </div>


          <div className="metric risk">

            <span className="metric-label">
              NETWORK RISK
            </span>

            <strong>
              {networkRisk.label}
            </strong>

          </div>


          <div className="telemetry">

            <span
              className={`status-dot ${
                backendOnline
                  ? "online"
                  : "offline"
              }`}
            />

            {backendOnline
              ? "TELEMETRY CONNECTED"
              : "TELEMETRY DISCONNECTED"}

          </div>

        </footer>

      </main>

    </div>
  );
}

export default App;
