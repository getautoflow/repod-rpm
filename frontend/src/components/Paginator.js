/**
 * Paginator — Boutons Précédent / Suivant réutilisables.
 *
 * Props :
 *   page          {number}   page courante (1-indexé)
 *   pages         {number}   nombre total de pages
 *   total         {number}   nombre total d'éléments
 *   perPage       {number}   éléments par page
 *   onPageChange  {function} appelée avec le nouveau numéro de page
 *   loading       {boolean}  désactive les boutons pendant le chargement
 *
 * Renvoie null si pages <= 1.
 */
export default function Paginator({ page, pages, total, perPage, onPageChange, loading = false }) {
  if (!pages || pages <= 1) return null;

  const start = Math.min((page - 1) * perPage + 1, total);
  const end   = Math.min(page * perPage, total);

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "10px 16px",
      borderTop: "1px solid #f0f0f0",
      background: "#fafafa",
    }}>
      <span style={{ fontSize: "12px", color: "#888" }}>
        {start}–{end} sur <strong style={{ color: "#555" }}>{total}</strong> résultat{total !== 1 ? "s" : ""}
      </span>

      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1 || loading}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "4px",
            padding: "5px 10px",
            borderRadius: "6px",
            border: "1px solid #e0e0e0",
            fontSize: "12px",
            fontWeight: 500,
            color: "#555",
            background: "#fff",
            cursor: page <= 1 || loading ? "not-allowed" : "pointer",
            opacity: page <= 1 || loading ? 0.4 : 1,
          }}
        >
          <svg width="14" height="14" fill="none" viewBox="0 0 24 24"
               stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Préc.
        </button>

        <span style={{ fontSize: "12px", color: "#888", fontWeight: 500, padding: "0 6px", fontVariantNumeric: "tabular-nums" }}>
          {page} / {pages}
        </span>

        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page >= pages || loading}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "4px",
            padding: "5px 10px",
            borderRadius: "6px",
            border: "1px solid #e0e0e0",
            fontSize: "12px",
            fontWeight: 500,
            color: "#555",
            background: "#fff",
            cursor: page >= pages || loading ? "not-allowed" : "pointer",
            opacity: page >= pages || loading ? 0.4 : 1,
          }}
        >
          Suiv.
          <svg width="14" height="14" fill="none" viewBox="0 0 24 24"
               stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </button>
      </div>
    </div>
  );
}
