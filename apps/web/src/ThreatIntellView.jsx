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

function objectTone(stixObject) {
  if (stixObject.revoked) return "muted";
  if (["malware", "intrusion-set", "campaign"].includes(stixObject.type)) return "high";
  if (["tool", "indicator"].includes(stixObject.type)) return "medium";
  return "low";
}

function objectTags(stixObject) {
  return [
    externalIdFor(stixObject),
    ...(stixObject.x_mitre_domains || []),
    ...(stixObject.x_mitre_platforms || []).slice(0, 2),
  ].filter(Boolean);
}

function feedTypeCounts(objects) {
  return objects.reduce((acc, item) => {
    acc[item.type] = (acc[item.type] || 0) + 1;
    return acc;
  }, {});
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
  const [quickSearch, setQuickSearch] = useState("");
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
  const filteredObjects = useMemo(() => {
    const term = quickSearch.trim().toLowerCase();
    if (!term) return objects;
    return objects.filter((item) => {
      const summary = summarizeObject(item);
      return [summary.name, summary.externalId, summary.id, summary.type, summary.description]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(term));
    });
  }, [objects, quickSearch]);
  const typeCounts = useMemo(() => feedTypeCounts(objects), [objects]);
  const selectedSource = useMemo(() => sources.find((source) => source.id === selectedSourceId), [sources, selectedSourceId]);

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

  return (
    <section className="threat-layout">
      <div className="panel threat-panel threat-hero-panel">
        <div className="panel-head threat-hero-head">
          <div>
            <p className="eyebrow">TAXII 2.1 • Threat Intelligence Feeds</p>
            <h2>Threat Intell</h2>
            <p className="muted-line">Consulta operacional de fontes STIX/TAXII com leitura estruturada para analistas.</p>
          </div>
          <div className="mitre-meta-strip">
            <span className="mitre-chip">Fonte: {selectedSource?.name || "MITRE ATT&CK"}</span>
            <span className="mitre-chip">Formato: STIX 2.1</span>
          </div>
        </div>

        <div className="threat-command-bar">
          <span className="threat-command-prompt">&gt;_</span>
          <input
            type="search"
            value={quickSearch}
            onChange={(event) => setQuickSearch(event.target.value)}
            placeholder="Filtrar objetos carregados por nome, ID, tipo ou descrição"
          />
          <button className="ghost-button" type="button" onClick={() => setQuickSearch("")}>
            Limpar
          </button>
        </div>

        <div className="mitre-status" aria-live="polite">{status}</div>

        <div className="threat-summary-grid">
          <article className="mitre-summary-card">
            <p className="mitre-summary-label">Fontes</p>
            <p className="mitre-summary-value">{sources.length}</p>
          </article>
          <article className="mitre-summary-card">
            <p className="mitre-summary-label">Coleções</p>
            <p className="mitre-summary-value">{collections.length}</p>
          </article>
          <article className="mitre-summary-card">
            <p className="mitre-summary-label">Manifesto</p>
            <p className="mitre-summary-value">{manifestObjects.length}</p>
          </article>
          <article className="mitre-summary-card">
            <p className="mitre-summary-label">Objetos</p>
            <p className="mitre-summary-value">{objects.length}</p>
          </article>
        </div>
      </div>

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

        <section className="panel threat-panel threat-results-panel">
          <div className="panel-head">
            <div>
              <h2>Objetos STIX</h2>
              <p className="muted-line">{filteredObjects.length} em exibição de {objects.length} retornados.</p>
            </div>
            <div className="threat-type-filter">
              {OBJECT_TYPES.slice(0, 5).map((type) => (
                <button key={type} type="button" className={`type-pill ${filters.type === type ? "type-pill-active" : ""}`} onClick={() => setFilters((current) => ({ ...current, type }))}>
                  {typeCounts[type] || 0} {type}
                </button>
              ))}
            </div>
          </div>

          {filteredObjects.length ? (
            <div className="threat-object-list">
              {filteredObjects.map((item) => {
                const summary = summarizeObject(item);
                const tone = objectTone(item);
                return (
                  <button
                    key={`${summary.id}-${summary.modified}`}
                    type="button"
                    className={`threat-object-card threat-object-card-${tone} ${activeObject?.id === item.id ? "threat-object-card-active" : ""}`}
                    onClick={() => setActiveObject(item)}
                  >
                    <span className="history-card-top">
                      <strong>{summary.name}</strong>
                      <span className="mitre-id-badge">{summary.type}</span>
                    </span>
                    <span className="muted-line">{summary.externalId || summary.id}</span>
                    {summary.description ? <p>{summary.description}</p> : null}
                    <span className="threat-object-tags">
                      {objectTags(item).map((tag) => (
                        <span key={tag}>{tag}</span>
                      ))}
                    </span>
                    {summary.modified ? <small>{summary.modified}</small> : null}
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <h3>Nenhum objeto carregado</h3>
              <p className="muted-line">Selecione uma coleção e execute uma consulta filtrada.</p>
            </div>
          )}
        </section>
      </div>

      <div className="threat-bottom-grid">
        <div className="panel threat-panel">
          <div className="panel-head">
            <div>
              <h2>Distribuição do feed</h2>
              <p className="muted-line">Resumo dos objetos retornados por tipo STIX.</p>
            </div>
          </div>
          <div className="threat-distribution-list">
            {Object.entries(typeCounts).length ? (
              Object.entries(typeCounts)
                .sort((a, b) => b[1] - a[1])
                .map(([type, count]) => (
                  <div className="threat-distribution-row" key={type}>
                    <span>{type}</span>
                    <strong>{count}</strong>
                    <span style={{ width: `${Math.max(10, (count / Math.max(objects.length, 1)) * 100)}%` }} />
                  </div>
                ))
            ) : (
              <p className="muted-line">Execute uma consulta para ver distribuição.</p>
            )}
          </div>
        </div>

        <div className="panel threat-panel">
          <div className="panel-head">
            <div>
              <h2>Manifesto / Detalhe</h2>
              <p className="muted-line">Preview bruto para inspeção técnica e integrações futuras.</p>
            </div>
          </div>
          <pre className="threat-json-view">{compactJson(manifestPayload?.data || objectsPayload?.data || {})}</pre>
        </div>
      </div>

      <ThreatObjectModal stixObject={activeObject} onClose={() => setActiveObject(null)} />
    </section>
  );
}
