import { useEffect, useMemo, useState } from "react";
import { api } from "./api";

const OBJECT_TYPES = ["attack-pattern", "campaign", "course-of-action", "intrusion-set", "malware", "tool", "indicator", "relationship"];

function collectionLabel(collection) {
  return collection?.title || collection?.id || "Unknown collection";
}

function externalIdFor(stixObject) {
  const ref = stixObject?.external_references?.find((item) => item.external_id);
  return ref?.external_id || "";
}

function summarizeObject(stixObject) {
  return {
    id: stixObject.id,
    type: stixObject.type,
    name: stixObject.name || externalIdFor(stixObject) || stixObject.id,
    externalId: externalIdFor(stixObject),
    modified: stixObject.modified || stixObject.created || "",
    description: stixObject.description || stixObject.x_mitre_detection || "",
  };
}

function severityFor(stixObject) {
  if (stixObject.revoked) return "low";
  if (stixObject.confidence >= 80) return "high";
  if (stixObject.confidence >= 40) return "medium";
  if (stixObject.type === "malware" || stixObject.type === "intrusion-set" || stixObject.type === "campaign") return "high";
  return "low";
}

function ageFor(value) {
  if (!value) return "unknown age";
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return "unknown age";
  const days = Math.max(0, Math.round((Date.now() - timestamp) / 86400000));
  if (days === 0) return "today";
  if (days === 1) return "1 day ago";
  return `${days} days ago`;
}

function tagsFor(stixObject) {
  return [
    externalIdFor(stixObject),
    ...(stixObject.x_mitre_platforms || []).slice(0, 2),
    ...(stixObject.x_mitre_domains || []).slice(0, 1),
  ].filter(Boolean);
}

function matchesObjectSearch(stixObject, query) {
  const normalized = String(query || "").trim().toLowerCase();
  if (!normalized) return true;
  const summary = summarizeObject(stixObject);
  return [summary.name, summary.type, summary.externalId, summary.id, summary.description]
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(normalized));
}

function compactJson(value) {
  return JSON.stringify(value, null, 2);
}

function listValue(value) {
  if (Array.isArray(value)) return value.filter(Boolean).join(", ");
  return value || "—";
}

function formatDate(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function objectUrl(stixObject) {
  const ref = stixObject?.external_references?.find((item) => item.url);
  return ref?.url || "";
}

function DataPoint({ label, value }) {
  return (
    <div className="threat-detail-row">
      <span>{label}</span>
      <strong>{value || "—"}</strong>
    </div>
  );
}

function ChipList({ items }) {
  const values = Array.isArray(items) ? items.filter(Boolean) : [];
  if (!values.length) return <p className="muted-line">Nenhum dado informado.</p>;
  return (
    <div className="threat-chip-list">
      {values.map((item) => (
        <span className="mitre-chip" key={item}>
          {item}
        </span>
      ))}
    </div>
  );
}

function ThreatObjectModal({ stixObject, onClose }) {
  if (!stixObject) return null;
  const summary = summarizeObject(stixObject);
  const url = objectUrl(stixObject);
  const killChain = stixObject.kill_chain_phases || [];
  const references = stixObject.external_references || [];
  const aliases = stixObject.aliases || stixObject.x_mitre_aliases || [];
  const relatedRefs = [
    ...(stixObject.object_marking_refs || []),
    ...(stixObject.created_by_ref ? [stixObject.created_by_ref] : []),
    ...(stixObject.source_ref ? [stixObject.source_ref] : []),
    ...(stixObject.target_ref ? [stixObject.target_ref] : []),
  ];

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <article className="threat-detail-modal" role="dialog" aria-modal="true" aria-labelledby="threat-detail-title" onMouseDown={(event) => event.stopPropagation()}>
        <header className="threat-detail-hero">
          <div>
            <p className="eyebrow">{summary.type} • STIX 2.1</p>
            <h2 id="threat-detail-title">{summary.name}</h2>
            <p className="muted-line threat-detail-id">{summary.externalId || summary.id}</p>
          </div>
          <div className="threat-detail-actions">
            {url ? (
              <a className="ghost-button" href={url} target="_blank" rel="noreferrer">
                Abrir fonte
              </a>
            ) : null}
            <button type="button" className="ghost-button" onClick={onClose}>
              Fechar
            </button>
          </div>
        </header>

        <section className="threat-detail-grid">
          <DataPoint label="Tipo" value={summary.type} />
          <DataPoint label="Confiança" value={stixObject.confidence ? `${stixObject.confidence}/100` : "—"} />
          <DataPoint label="Criado" value={formatDate(stixObject.created)} />
          <DataPoint label="Modificado" value={formatDate(stixObject.modified)} />
          <DataPoint label="Versão MITRE" value={stixObject.x_mitre_version} />
          <DataPoint label="Revogado" value={stixObject.revoked ? "Sim" : "Não"} />
        </section>

        <div className="threat-detail-content">
          <section className="threat-detail-card threat-detail-card-wide">
            <h3>Descrição</h3>
            <p>{stixObject.description || "Sem descrição disponível."}</p>
          </section>

          {stixObject.x_mitre_detection ? (
            <section className="threat-detail-card threat-detail-card-wide">
              <h3>Detecção</h3>
              <p>{stixObject.x_mitre_detection}</p>
            </section>
          ) : null}

          {stixObject.pattern ? (
            <section className="threat-detail-card threat-detail-card-wide">
              <h3>Padrão indicador</h3>
              <pre className="threat-inline-code">{stixObject.pattern}</pre>
            </section>
          ) : null}

          <section className="threat-detail-card">
            <h3>Kill chain</h3>
            {killChain.length ? (
              <div className="threat-killchain">
                {killChain.map((phase) => (
                  <span className="mitre-chip" key={`${phase.kill_chain_name}-${phase.phase_name}`}>
                    {phase.kill_chain_name}: {phase.phase_name}
                  </span>
                ))}
              </div>
            ) : (
              <p className="muted-line">Sem fase associada.</p>
            )}
          </section>

          <section className="threat-detail-card">
            <h3>Plataformas</h3>
            <ChipList items={stixObject.x_mitre_platforms} />
          </section>

          <section className="threat-detail-card">
            <h3>Data sources</h3>
            <ChipList items={stixObject.x_mitre_data_sources} />
          </section>

          <section className="threat-detail-card">
            <h3>Aliases / Domínios</h3>
            <ChipList items={[...aliases, ...(stixObject.x_mitre_domains || [])]} />
          </section>

          <section className="threat-detail-card threat-detail-card-wide">
            <h3>Referências externas</h3>
            {references.length ? (
              <div className="threat-reference-list">
                {references.map((reference, index) => (
                  <a href={reference.url || "#"} target="_blank" rel="noreferrer" className="threat-reference-card" key={`${reference.source_name}-${index}`}>
                    <strong>{reference.external_id || reference.source_name || "Referência"}</strong>
                    <span>{reference.source_name || "Fonte externa"}</span>
                    {reference.description ? <p>{reference.description}</p> : null}
                  </a>
                ))}
              </div>
            ) : (
              <p className="muted-line">Nenhuma referência externa.</p>
            )}
          </section>

          <section className="threat-detail-card threat-detail-card-wide">
            <h3>Relacionamentos e marcações</h3>
            <ChipList items={relatedRefs} />
          </section>

          <details className="threat-detail-card threat-detail-card-wide">
            <summary>STIX JSON bruto</summary>
            <pre className="threat-json-view threat-json-view-modal">{compactJson(stixObject)}</pre>
          </details>
        </div>
      </article>
    </div>
  );
}

export function ThreatIntellView({ token }) {
  const [sources, setSources] = useState([]);
  const [collections, setCollections] = useState([]);
  const [selectedSourceId, setSelectedSourceId] = useState("mitre-attack");
  const [selectedCollectionId, setSelectedCollectionId] = useState("");
  const [filters, setFilters] = useState({ type: "attack-pattern", id: "", added_after: "" });
  const [status, setStatus] = useState("Carregando fontes TAXII...");
  const [objectsPayload, setObjectsPayload] = useState(null);
  const [manifestPayload, setManifestPayload] = useState(null);
  const [activeObject, setActiveObject] = useState(null);
  const [globalQuery, setGlobalQuery] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadSources() {
      try {
        const payload = await api.listTaxiiSources(token);
        if (cancelled) return;
        setSources(payload);
        setSelectedSourceId((current) => current || payload[0]?.id || "mitre-attack");
        setStatus(`${payload.length} fonte TAXII disponível.`);
      } catch (error) {
        if (!cancelled) setStatus(`Não foi possível carregar fontes TAXII. Detalhe: ${error.message}`);
      }
    }

    loadSources();
    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => {
    if (!selectedSourceId) return;
    let cancelled = false;

    async function loadCollections() {
      setStatus("Carregando coleções TAXII...");
      try {
        const payload = await api.getTaxiiCollections(token, selectedSourceId);
        if (cancelled) return;
        const nextCollections = payload.data?.collections || [];
        setCollections(nextCollections);
        setSelectedCollectionId((current) => current || nextCollections[0]?.id || "");
        setStatus(`${nextCollections.length} coleções disponíveis em ${payload.source.name}.`);
      } catch (error) {
        if (!cancelled) setStatus(`Não foi possível carregar coleções. Detalhe: ${error.message}`);
      }
    }

    loadCollections();
    return () => {
      cancelled = true;
    };
  }, [token, selectedSourceId]);

  const selectedCollection = useMemo(
    () => collections.find((collection) => collection.id === selectedCollectionId),
    [collections, selectedCollectionId],
  );

  const objects = useMemo(() => objectsPayload?.data?.objects || [], [objectsPayload]);
  const manifestObjects = useMemo(() => manifestPayload?.data?.objects || [], [manifestPayload]);
  const visibleObjects = useMemo(() => objects.filter((item) => matchesObjectSearch(item, globalQuery)), [objects, globalQuery]);
  const feedSnapshot = useMemo(() => {
    const counts = objects.reduce((acc, item) => {
      acc[item.type] = (acc[item.type] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
  }, [objects]);

  async function loadManifest(event) {
    event.preventDefault();
    if (!selectedSourceId || !selectedCollectionId) return;
    setLoading(true);
    setStatus("Consultando manifesto TAXII...");
    try {
      const payload = await api.getTaxiiManifest(token, selectedSourceId, selectedCollectionId, filters);
      setManifestPayload(payload);
      setStatus(`Manifesto carregado com ${payload.data?.objects?.length || 0} entradas.`);
    } catch (error) {
      setStatus(`Falha ao consultar manifesto. Detalhe: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function loadObjects(event) {
    event.preventDefault();
    if (!selectedSourceId || !selectedCollectionId) return;
    if (!filters.type && !filters.id && !filters.added_after) {
      setStatus("Informe ao menos um filtro antes de buscar objetos STIX.");
      return;
    }
    setLoading(true);
    setStatus("Consultando objetos STIX via TAXII...");
    try {
      const payload = await api.getTaxiiObjects(token, selectedSourceId, selectedCollectionId, filters);
      setObjectsPayload(payload);
      setActiveObject(null);
      setStatus(`Objetos carregados: ${payload.data?.objects?.length || 0}.`);
    } catch (error) {
      setStatus(`Falha ao consultar objetos. Detalhe: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  function executeGlobalSearch(event) {
    event.preventDefault();
    const query = globalQuery.trim();
    if (!query) {
      loadObjects(event);
      return;
    }
    if (OBJECT_TYPES.includes(query)) {
      setFilters((current) => ({ ...current, type: query, id: "" }));
      return;
    }
    if (query.includes("--")) {
      setFilters((current) => ({ ...current, id: query, type: "" }));
    }
  }

  return (
    <section className="threat-layout">
      <section className="threat-search-zone">
        <form className="threat-global-search" onSubmit={executeGlobalSearch}>
          <p className="eyebrow">Threat Intelligence / Global Search</p>
          <div className="threat-search-box">
            <span className="threat-prompt">&gt;_</span>
            <input
              type="search"
              value={globalQuery}
              onChange={(event) => setGlobalQuery(event.target.value)}
              placeholder="Enter a STIX ID, type, ATT&CK ID, malware, tool, or campaign"
              aria-label="Threat intelligence global search"
            />
            <button className="primary-button" type="submit" disabled={loading}>
              Execute
            </button>
          </div>
          <div className="threat-search-tips">
            <span>Tip: use <strong>attack-pattern</strong> for techniques</span>
            <span>Tip: paste a STIX ID for exact lookup</span>
          </div>
        </form>
      </section>

      <section className="threat-feed-section">
        <div className="threat-feed-head">
          <div>
            <h2>Recent Intelligence</h2>
            <p className="muted-line">Live TAXII feed indexed from configured CTI sources</p>
          </div>
          <span className="threat-archive-link">View feed archive -&gt;</span>
        </div>

        {visibleObjects.length ? (
          <div className="threat-feed-grid">
            {visibleObjects.slice(0, 8).map((item) => {
              const summary = summarizeObject(item);
              const severity = severityFor(item);
              return (
                <button key={`${summary.id}-${summary.modified}`} type="button" className={`threat-feed-card threat-feed-card-${severity}`} onClick={() => setActiveObject(item)}>
                  <span className="threat-feed-icon">{summary.type.slice(0, 2).toUpperCase()}</span>
                  <span className="threat-feed-content">
                    <span className="threat-feed-topline">
                      <strong>{summary.name}</strong>
                      <span className={`threat-severity threat-severity-${severity}`}>{severity}</span>
                    </span>
                    <span className="threat-feed-source">MITRE ATT&CK • {ageFor(summary.modified)}</span>
                    <span className="threat-feed-desc">{summary.description || "No narrative summary provided by the TAXII object."}</span>
                    <span className="threat-feed-tags">
                      {tagsFor(item).map((tag) => (
                        <span key={tag}>{tag}</span>
                      ))}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        ) : (
          <div className="empty-state threat-empty-feed">
            <h3>No feed objects loaded</h3>
            <p className="muted-line">Run a TAXII query below to populate recent intelligence.</p>
          </div>
        )}
      </section>

      <div className="threat-grid">
        <aside className="panel threat-panel">
          <div className="panel-head">
            <div>
              <h2>Consulta TAXII</h2>
              <p className="muted-line">Use filtros para consultar coleções sem puxar bundles grandes.</p>
            </div>
          </div>

          <form className="analysis-form" onSubmit={loadObjects}>
            <label>
              Fonte
              <select value={selectedSourceId} onChange={(event) => setSelectedSourceId(event.target.value)}>
                {sources.map((source) => (
                  <option key={source.id} value={source.id}>
                    {source.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Coleção
              <select value={selectedCollectionId} onChange={(event) => setSelectedCollectionId(event.target.value)}>
                {collections.map((collection) => (
                  <option key={collection.id} value={collection.id}>
                    {collectionLabel(collection)}
                  </option>
                ))}
              </select>
            </label>
            {selectedCollection ? <p className="muted-line">{selectedCollection.description}</p> : null}

            <label>
              Tipo STIX
              <select value={filters.type} onChange={(event) => setFilters((current) => ({ ...current, type: event.target.value }))}>
                <option value="">Qualquer tipo</option>
                {OBJECT_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </label>
            <label>
              STIX ID
              <input
                type="text"
                value={filters.id}
                onChange={(event) => setFilters((current) => ({ ...current, id: event.target.value }))}
                placeholder="attack-pattern--..."
              />
            </label>
            <label>
              Added after
              <input
                type="text"
                value={filters.added_after}
                onChange={(event) => setFilters((current) => ({ ...current, added_after: event.target.value }))}
                placeholder="2024-01-01"
              />
            </label>

            <div className="threat-actions">
              <button className="ghost-button" type="button" onClick={loadManifest} disabled={loading || !selectedCollectionId}>
                Manifesto
              </button>
              <button className="primary-button action-button" type="submit" disabled={loading || !selectedCollectionId}>
                {loading ? "Consultando..." : "Buscar STIX"}
              </button>
            </div>
          </form>
        </aside>

        <section className="panel threat-panel">
          <div className="panel-head">
            <div>
              <h2>Feed Distribution Snapshot</h2>
              <p className="muted-line">Current result set by STIX object type.</p>
            </div>
          </div>

          {feedSnapshot.length ? (
            <div className="threat-distribution">
              {feedSnapshot.map(([type, count]) => (
                <div className="threat-distribution-row" key={type}>
                  <span>{type}</span>
                  <strong>{count}</strong>
                  <span style={{ width: `${Math.max(8, (count / Math.max(objects.length, 1)) * 100)}%` }} />
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <h3>No distribution data</h3>
              <p className="muted-line">Execute a STIX query to build a feed snapshot.</p>
            </div>
          )}
        </section>
      </div>

      {manifestPayload || objectsPayload ? (
        <div className="panel threat-panel">
          <div className="panel-head">
            <div>
              <h2>Feed Summary</h2>
              <p className="muted-line">Raw TAXII response preview for analysts and integrations.</p>
            </div>
          </div>
          <pre className="threat-json-view">{compactJson(manifestPayload?.data || objectsPayload?.data || {})}</pre>
        </div>
      ) : null}

      <ThreatObjectModal stixObject={activeObject} onClose={() => setActiveObject(null)} />
    </section>
  );
}
