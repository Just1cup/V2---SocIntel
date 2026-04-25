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

function compactJson(value) {
  return JSON.stringify(value, null, 2);
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
      <div className="panel threat-panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">TAXII 2.1 • Threat Intelligence Feeds</p>
            <h2>Threat Intell</h2>
          </div>
          <div className="mitre-meta-strip">
            <span className="mitre-chip">Fonte: MITRE ATT&CK</span>
            <span className="mitre-chip">Formato: STIX 2.1</span>
          </div>
        </div>

        <div className="mitre-status" aria-live="polite">
          {status}
        </div>

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

        <section className="panel threat-panel">
          <div className="panel-head">
            <div>
              <h2>Objetos STIX</h2>
              <p className="muted-line">Resultados retornados diretamente do feed TAXII configurado.</p>
            </div>
          </div>

          {objects.length ? (
            <div className="threat-object-list">
              {objects.map((item) => {
                const summary = summarizeObject(item);
                return (
                  <button
                    key={`${summary.id}-${summary.modified}`}
                    type="button"
                    className={`threat-object-card ${activeObject?.id === item.id ? "threat-object-card-active" : ""}`}
                    onClick={() => setActiveObject(item)}
                  >
                    <span className="history-card-top">
                      <strong>{summary.name}</strong>
                      <span className="mitre-id-badge">{summary.type}</span>
                    </span>
                    <span className="muted-line">{summary.externalId || summary.id}</span>
                    {summary.description ? <p>{summary.description}</p> : null}
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

      <div className="panel threat-panel">
        <div className="panel-head">
          <div>
            <h2>{activeObject ? "Objeto selecionado" : "Manifesto / Detalhe"}</h2>
            <p className="muted-line">Visualização JSON para inspeção técnica e integração futura.</p>
          </div>
        </div>
        <pre className="threat-json-view">{compactJson(activeObject || manifestPayload?.data || objectsPayload?.data || {})}</pre>
      </div>
    </section>
  );
}

