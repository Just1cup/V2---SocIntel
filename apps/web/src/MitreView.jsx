import { useEffect, useState } from "react";
import { api } from "./api";

function normalizeSearch(value) {
  return String(value || "").trim().toLowerCase();
}

function matchesSearch(text, searchTerm) {
  const term = normalizeSearch(searchTerm);
  if (!term) return false;
  return normalizeSearch(text).includes(term);
}

function getDisplayName(item) {
  return item.namePt || item.name || "Sem nome disponível";
}

function getDescriptionText(item) {
  return item?.descriptionPt || item?.description || "Sem descrição disponível.";
}

function mitrePathById(externalId, kind) {
  if (!externalId) return "https://attack.mitre.org/";
  if (kind === "tactic") return `https://attack.mitre.org/tactics/${externalId}/`;
  if (kind === "technique") return `https://attack.mitre.org/techniques/${externalId.replace(".", "/")}/`;
  return "https://attack.mitre.org/";
}

function filterCatalog(catalog, searchTerm) {
  const term = normalizeSearch(searchTerm);
  if (!term) return catalog;

  const tactics = catalog.tactics
    .map((tactic) => {
      const techniques = tactic.techniques
        .filter((technique) => {
          const techniqueText = `${technique.externalId} ${technique.name} ${technique.namePt || ""}`;
          const matchingSubs = technique.subtechniques.filter((sub) =>
            matchesSearch(`${sub.externalId} ${sub.name} ${sub.namePt || ""}`, term),
          );
          return matchesSearch(techniqueText, term) || matchingSubs.length > 0;
        })
        .map((technique) => {
          const techniqueText = `${technique.externalId} ${technique.name} ${technique.namePt || ""}`;
          const filteredSubs = matchesSearch(techniqueText, term)
            ? technique.subtechniques
            : technique.subtechniques.filter((sub) =>
                matchesSearch(`${sub.externalId} ${sub.name} ${sub.namePt || ""}`, term),
              );
          return { ...technique, subtechniques: filteredSubs };
        });

      return { ...tactic, techniques };
    })
    .filter((tactic) => tactic.techniques.length > 0);

  return { ...catalog, tactics };
}

function createCopyLinkHandler(url, setStatus) {
  return async (event) => {
    event.preventDefault();
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(url);
      setStatus(`Link copiado: ${url}`);
    } catch {
      setStatus("Não foi possível copiar o link do MITRE.");
    }
  };
}

export function MitreView({ token }) {
  const [catalog, setCatalog] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [status, setStatus] = useState("Carregando catálogo do MITRE ATT&CK...");
  const [techniqueDetails, setTechniqueDetails] = useState({});
  const [loadingTechniqueIds, setLoadingTechniqueIds] = useState({});

  useEffect(() => {
    let cancelled = false;

    async function loadCatalog() {
      try {
        const payload = await api.getMitreIndex(token);
        if (cancelled) return;
        setCatalog(payload);
        setStatus(
          `Catálogo local carregado com ${payload.tacticCount} táticas, ${payload.techniqueCount} técnicas e ${payload.subtechniqueCount} sub-técnicas.`,
        );
      } catch (error) {
        if (!cancelled) {
          setStatus(`Não foi possível carregar o catálogo do MITRE ATT&CK. Detalhe: ${error.message}`);
        }
      }
    }

    loadCatalog();
    return () => {
      cancelled = true;
    };
  }, [token]);

  const filteredCatalog = catalog ? filterCatalog(catalog, searchTerm) : null;

  useEffect(() => {
    if (!filteredCatalog) return;
    if (normalizeSearch(searchTerm)) {
      const visibleTechniques = filteredCatalog.tactics.reduce((sum, tactic) => sum + tactic.techniques.length, 0);
      const visibleSubs = filteredCatalog.tactics.reduce(
        (sum, tactic) => sum + tactic.techniques.reduce((inner, technique) => inner + technique.subtechniques.length, 0),
        0,
      );
      setStatus(
        `Filtro aplicado: "${searchTerm}". ${filteredCatalog.tactics.length} táticas, ${visibleTechniques} técnicas e ${visibleSubs} sub-técnicas em exibição.`,
      );
      return;
    }
    setStatus(
      `Catálogo local carregado com ${catalog.tacticCount} táticas, ${catalog.techniqueCount} técnicas e ${catalog.subtechniqueCount} sub-técnicas.`,
    );
  }, [catalog, filteredCatalog, searchTerm]);

  async function loadTechniqueDetail(externalId) {
    if (!externalId || techniqueDetails[externalId] || loadingTechniqueIds[externalId]) {
      return;
    }
    setLoadingTechniqueIds((current) => ({ ...current, [externalId]: true }));
    try {
      const payload = await api.getMitreTechniqueDetail(token, externalId);
      setTechniqueDetails((current) => ({ ...current, [externalId]: payload }));
    } catch (error) {
      setStatus(`Não foi possível carregar detalhes de ${externalId}. Detalhe: ${error.message}`);
    } finally {
      setLoadingTechniqueIds((current) => ({ ...current, [externalId]: false }));
    }
  }

  if (!filteredCatalog) {
    return (
      <section className="mitre-layout">
        <div className="panel mitre-panel">
          <div className="empty-state">
            <h3>Carregando MITRE ATT&CK</h3>
            <p className="muted-line">Preparando o índice local de táticas, técnicas e sub-técnicas.</p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="mitre-layout">
      <div className="panel mitre-panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">Knowledge Base • Enterprise ATT&CK Catalog</p>
            <h2>MITRE ATT&CK</h2>
          </div>
          <div className="mitre-meta-strip">
            <span className="mitre-chip">Coleção: Enterprise ATT&CK</span>
            <span className="mitre-chip">Origem: índice estático via API</span>
          </div>
        </div>

        <div className="mitre-summary-grid" aria-label="Resumo do catálogo">
          <article className="mitre-summary-card">
            <p className="mitre-summary-label">Táticas</p>
            <p className="mitre-summary-value">{catalog.tacticCount}</p>
          </article>
          <article className="mitre-summary-card">
            <p className="mitre-summary-label">Técnicas</p>
            <p className="mitre-summary-value">{catalog.techniqueCount}</p>
          </article>
          <article className="mitre-summary-card">
            <p className="mitre-summary-label">Sub-técnicas</p>
            <p className="mitre-summary-value">{catalog.subtechniqueCount}</p>
          </article>
          <article className="mitre-summary-card">
            <p className="mitre-summary-label">Fonte</p>
            <p className="mitre-summary-value">Static JSON</p>
          </article>
        </div>

        <div className="mitre-status" aria-live="polite">
          {status}
        </div>
      </div>

      <div className="panel mitre-panel">
        <div className="panel-head">
          <div>
            <h2>Matriz por Tática</h2>
            <p className="muted-line">Busca feita no índice. Descrições carregam apenas ao expandir a técnica.</p>
          </div>
        </div>

        <div className="mitre-search-row">
          <input
            id="mitreSearch"
            type="search"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            placeholder="Pesquisar técnica ou sub-técnica por ID ou nome"
            aria-label="Pesquisar técnica ou sub-técnica"
          />
        </div>

        <div className="mitre-tactics" aria-live="polite">
          {filteredCatalog.tactics.length ? (
            filteredCatalog.tactics.map((tactic) => (
              <details key={tactic.id} className="mitre-tactic-card" open>
                <summary className="mitre-toggle-head">
                  <div className="mitre-tactic-head">
                    <div>
                      <h3>{getDisplayName(tactic)}</h3>
                      <div className="mitre-technique-meta">
                        <span className="mitre-chip">Técnicas: {tactic.techniqueCount}</span>
                        <span className="mitre-chip">Sub-técnicas: {tactic.subtechniqueCount}</span>
                        <span className="mitre-chip">
                          Técnicas com sub: {tactic.techniques.filter((item) => item.subtechniqueCount > 0).length}
                        </span>
                      </div>
                    </div>
                    <div className="mitre-head-actions">
                      <span className="mitre-id-badge">{tactic.externalId || tactic.shortname}</span>
                      <button
                        type="button"
                        className="ghost-button mitre-copy-link"
                        onClick={createCopyLinkHandler(mitrePathById(tactic.externalId, "tactic"), setStatus)}
                      >
                        Copiar link
                      </button>
                    </div>
                  </div>
                </summary>

                <div className="mitre-toggle-body">
                  <details className="mitre-description">
                    <summary>Ver descrição</summary>
                    <p>{getDescriptionText(tactic)}</p>
                  </details>

                  <div className="mitre-technique-list">
                    {tactic.techniques.map((technique) => {
                      const hasSubtechniques = technique.subtechniqueCount > 0;
                      const techniqueMatches = matchesSearch(
                        `${technique.externalId} ${technique.name} ${technique.namePt || ""}`,
                        searchTerm,
                      );
                      const subMatchesSearch = technique.subtechniques.some((sub) =>
                        matchesSearch(`${sub.externalId} ${sub.name} ${sub.namePt || ""}`, searchTerm),
                      );
                      const detail = techniqueDetails[technique.externalId];
                      const techniqueDetail = detail?.technique;
                      const subtechniques = detail?.subtechniques || technique.subtechniques;

                      return (
                        <details
                          key={technique.id}
                          className={`mitre-technique-card ${
                            hasSubtechniques ? "mitre-technique-card-has-subs" : ""
                          } ${subMatchesSearch ? "mitre-technique-card-submatch" : ""}`}
                          open={Boolean(normalizeSearch(searchTerm))}
                          onToggle={(event) => {
                            if (event.currentTarget.open) {
                              loadTechniqueDetail(technique.externalId);
                            }
                          }}
                        >
                          <summary className="mitre-toggle-head">
                            <div className="mitre-technique-head">
                              <div>
                                <h4
                                  className={`mitre-technique-title ${
                                    techniqueMatches || subMatchesSearch ? "mitre-technique-title-match" : ""
                                  }`}
                                >
                                  {technique.externalId} - {getDisplayName(technique)}
                                </h4>
                                <div className="mitre-technique-meta">
                                  <span className="mitre-chip">
                                    Plataformas: {technique.platforms.length ? technique.platforms.join(", ") : "N/A"}
                                  </span>
                                  {hasSubtechniques ? (
                                    <span className="mitre-chip mitre-chip-highlight">Possui sub-técnicas</span>
                                  ) : null}
                                  {subMatchesSearch ? (
                                    <span className="mitre-chip mitre-chip-highlight">
                                      Correspondência em sub-técnicas
                                    </span>
                                  ) : null}
                                </div>
                              </div>
                              <div className="mitre-head-actions">
                                <span
                                  className={`mitre-id-badge ${hasSubtechniques ? "mitre-id-badge-highlight" : ""}`}
                                >
                                  {technique.subtechniqueCount} sub
                                </span>
                                <button
                                  type="button"
                                  className="ghost-button mitre-copy-link"
                                  onClick={createCopyLinkHandler(
                                    mitrePathById(technique.externalId, "technique"),
                                    setStatus,
                                  )}
                                >
                                  Copiar link
                                </button>
                              </div>
                            </div>
                          </summary>

                          <div className="mitre-toggle-body">
                            {loadingTechniqueIds[technique.externalId] && !detail ? (
                              <div className="empty-state">
                                <h3>Carregando detalhes</h3>
                                <p className="muted-line">Buscando descrições e subtécnicas da técnica {technique.externalId}.</p>
                              </div>
                            ) : (
                              <>
                                <details className="mitre-description">
                                  <summary>Ver descrição</summary>
                                  <p>{getDescriptionText(techniqueDetail || technique)}</p>
                                </details>

                                {subtechniques.length ? (
                                  <div className="mitre-sub-list">
                                    {subtechniques.map((sub) => (
                                      <div
                                        key={sub.id}
                                        className={`mitre-sub-card ${
                                          matchesSearch(`${sub.externalId} ${sub.name} ${sub.namePt || ""}`, searchTerm)
                                            ? "mitre-sub-card-match"
                                            : ""
                                        }`}
                                      >
                                        <div className="mitre-sub-head">
                                          <h5>
                                            {sub.externalId} - {getDisplayName(sub)}
                                          </h5>
                                          <button
                                            type="button"
                                            className="ghost-button mitre-copy-link"
                                            onClick={createCopyLinkHandler(
                                              mitrePathById(sub.externalId, "technique"),
                                              setStatus,
                                            )}
                                          >
                                            Copiar link
                                          </button>
                                        </div>
                                        {sub.platforms.length ? (
                                          <div className="mitre-technique-meta">
                                            <span className="mitre-chip">Plataformas: {sub.platforms.join(", ")}</span>
                                          </div>
                                        ) : null}
                                        {detail ? (
                                          <details className="mitre-description">
                                            <summary>Ver descrição</summary>
                                            <p>{getDescriptionText(sub)}</p>
                                          </details>
                                        ) : (
                                          <p className="muted-line">Descrição disponível após o carregamento dos detalhes.</p>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                ) : null}
                              </>
                            )}
                          </div>
                        </details>
                      );
                    })}
                  </div>
                </div>
              </details>
            ))
          ) : (
            <div className="empty-state">
              <h3>Nenhuma técnica encontrada</h3>
              <p className="muted-line">Ajuste o filtro para localizar outra técnica ou sub-técnica.</p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
