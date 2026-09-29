"""Control-relevance POLICY, with nothing but plain data crossing its edges.

No ``Session``, no ``LLMClient``, no network, no clock. Every decision this module makes —
what text a control query is built from, which ITOT labels a scenario is allowed to match,
which matches become map rows and in what order — is a function of its arguments alone, so it
can be unit-tested without a database, a fake LLM or a fixture. The IO half (fetching
candidates, embedding, reranking, inserting) stays in ``control_mapping``; this module is what
that half asks for an answer.

Each rule below exists because the mixed version of it measurably misbehaved:

* TWO QUERY BUILDERS DRIFTED. The generation pass and the remediation top-up each had a private
  builder in ``control_mapping`` (both since deleted) that built different text for the same
  scenario, so the same library could answer one and not the other. There is ONE builder here
  (``build_control_retrieval_query``) and both passes call it through
  ``control_mapping._retrieval_query``.
* ITOT MATCHING WAS ALL-OR-NOTHING. ``grounding.resolve_asset_labels`` returns ``None`` — "no
  filter at all" — the moment ANY one category fails to match the vocabulary, so a scenario
  whose categories were {IT, SOMETHING_NEW} lost the perfectly good IT label along with the
  unmatched one. ``ItotApplicabilityContext`` keeps the labels that DID match and reports the
  ids that did not, separately, so the caller can narrow AND know it narrowed on partial
  information.
* TRUNCATION WAS SILENT. ``select_matching_controls`` sliced to ``top_k`` and told nobody, so a
  scenario with 40 good controls and one with exactly 5 were indistinguishable afterwards.
  ``ControlSelection`` carries the counts that make the difference visible.

``grounding``/``control_mapping`` are deliberately NOT imported: both pull in SQLAlchemy and the
DB layer, and a policy module that cannot be imported without a configured database is a policy
module that will grow a query. The few text helpers they share are re-stated here as three-line
private functions instead.
"""
from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any


def _clean_text(value: Any) -> str:
    """A trimmed string, or "" for anything that is not one.

    Same defence as ``grounding.ensure_text``: scenario JSON is model-authored, so a field that
    should be a string arrives as a dict, a number or ``None`` often enough that every reader
    here has to survive it rather than raise three frames later.
    """
    return value.strip() if isinstance(value, str) else ""


def _joined_labels(prefix: str, values: Iterable[str] | None) -> str:
    """``"Threat actors: APT33, insider"`` — or "" when nothing usable was supplied.

    The prefix is kept (the top-up's since-deleted private builder already emitted it) because the
    keyword leg of the hybrid shortlist tokenizes this text: a bare comma-joined list reads as
    part of the preceding sentence, and the labelled form survives the reader's eye in a logged
    query too. Blank entries are dropped rather than rendered as empty list slots.
    """
    cleaned = [text for text in (_clean_text(value) for value in (values or ())) if text]
    return f"{prefix}: {', '.join(cleaned)}" if cleaned else ""


def _clip_on_word_boundary(text: str, max_chars: int) -> str | None:
    """``text`` cut to ``max_chars`` at the last whitespace before the limit; ``None`` if empty.

    A word boundary, not a hard slice: the tail of this query is asset/system context, and half
    an identifier ("Siemens S7-15") is a token the BM25 leg cannot match while still costing the
    reranker its budget. ``max_chars <= 0`` means "no ceiling" — a caller that has no configured
    limit should get the whole query rather than the empty string.

    A limit landing exactly ON a space keeps the word before it: backing off one more word there
    would drop a whole term to respect a boundary the text already honoured.
    """
    if not text or max_chars <= 0 or len(text) <= max_chars:
        return text or None
    head = text[:max_chars]
    if text[max_chars] != " " and " " in head:
        head = head.rsplit(" ", 1)[0]
    return head.rstrip() or None


def build_control_retrieval_query(*, threat_category: Any, threat_type: Any, threat_name: Any,
                                  threat_actors: Iterable[str] | None, scenario_title: Any,
                                  scenario_statement: Any, risk_statement: Any, asset_name: Any,
                                  asset_technology: Any, involved_system_names: Iterable[str] | None,
                                  max_chars: int) -> str | None:
    """The ONE control-retrieval query text, for the generation pass and the top-up alike.

    THE ORDER IS MEASURED, not stylistic. A scenario narrative describes the IMPACT ("telemetry
    severed", "availability degraded"); controls address the MECHANISM ("compromised vendor
    firmware"). Querying on narrative alone therefore matched impact-shaped controls and buried
    mechanism-shaped ones: on a real "Compromised OT supply chain or hardware" scenario the
    reranker scored ``Telecommunications Services Availability`` 14.0 and the actually-correct
    ``Signed Components`` 1.9 — nothing cleared the cutoff and the API published ``controls: []``,
    which the schemas document as a genuine library gap. Prefixing the threat identity moved
    ``Signed Components`` to 60.6 and ``Supply Chain Risk Assessment`` to 90.98 against the SAME
    library, reranker and threshold. So threat identity LEADS, always:

        category, type, name, actors, scenario title, scenario statement, risk statement,
        asset name + technology, involved system names

    and the asset/system context TRAILS, where the clip below is most likely to bite it — the
    part of the text whose loss costs the least.

    Every part is optional and blanks are skipped, so one builder serves the generation pass
    (which has no risk statement yet) and the remediation top-up (which has everything) without
    either of them growing a second builder — the exact drift this replaces. ``None`` comes back
    when nothing groundable remained, which the caller must treat as "do not ask", never as an
    empty query.
    """
    asset_context = " ".join(text for text in (_clean_text(asset_name),
                                               _clean_text(asset_technology)) if text)
    parts = (_clean_text(threat_category), _clean_text(threat_type), _clean_text(threat_name),
             _joined_labels("Threat actors", threat_actors),
             _clean_text(scenario_title), _clean_text(scenario_statement),
             _clean_text(risk_statement), asset_context,
             _joined_labels("Involved systems", involved_system_names))
    return _clip_on_word_boundary(" ".join(part for part in parts if part), max_chars)


@dataclass(frozen=True)
class ItotApplicabilityContext:
    """Which ITOT labels one scenario may match, AND what could not be answered.

    ``derived_from`` is "scenario" when the scenario's own systems decided it, "session" when it
    fell back to the session's categories, "none" when there was nothing to derive from. It is a
    field rather than something the caller infers because those three produce the same
    ``labels`` tuple often enough to be indistinguishable afterwards, and "this scenario named no
    systems, so it inherited the session's" is exactly the kind of fact a reviewer needs when a
    mapping looks too wide.

    ``unrepresented_category_ids`` is the fix for a measured defect: the shared
    ``grounding.resolve_asset_labels`` abandons the WHOLE filter as soon as one category fails to
    match the vocabulary, so a scenario categorised {IT, <new category>} silently stopped
    narrowing on IT as well. Here the matched labels survive and the unmatched ids are reported
    beside them, so the caller can narrow on what is known and still record that it did so on
    partial information.
    """

    labels: tuple[str, ...] = ()
    unrepresented_category_ids: tuple[int, ...] = ()
    derived_from: str = "none"

    @property
    def is_complete(self) -> bool:
        """True when every category matched a label and at least one label came out.

        False is not an error — it is the "narrowed on partial information" signal above, and the
        audit trail is expected to record it rather than the caller to branch on it.
        """
        return not self.unrepresented_category_ids and bool(self.labels)


def _vocabulary_by_fold(vocabulary: Iterable[str]) -> dict[str, str]:
    """{casefolded label: label as the library spells it}, built in sorted order.

    Sorted because the parenthesised-marker search below scans this mapping and returns the first
    hit: fed a ``set`` (which is what ``grounding.control_itot_vocabulary`` returns) insertion
    order varies per process, and a category matching two markers would resolve differently on
    two workers reading the same row.
    """
    return {label.casefold(): label
            for label in sorted({_clean_text(value) for value in vocabulary} - {""})}


def _match_category_to_vocabulary(code: Any, name: Any, by_fold: Mapping[str, str]) -> str | None:
    """One category's ITOT label, or ``None`` when the vocabulary cannot represent it.

    Copied deliberately from ``grounding.resolve_asset_labels`` so the two cannot answer the same
    category differently: the CODE is matched case-insensitively first, then a PARENTHESISED
    ``(CODE)`` marker inside the category NAME. Parenthesised, never substring — "IT" appears
    inside "FACILITIES", and a substring test therefore labelled a facilities category as IT.
    """
    matched = by_fold.get(_clean_text(code).casefold())
    if matched is not None:
        return matched
    folded_name = _clean_text(name).casefold()
    return next((label for fold, label in by_fold.items() if f"({fold})" in folded_name), None)


def _resolve_category_ids(category_ids: Iterable[int],
                          category_code_by_id: Mapping[int, tuple[Any, Any]],
                          vocabulary: Iterable[str], derived_from: str) -> ItotApplicabilityContext:
    """Match a concrete set of category ids, keeping the hits and reporting the misses.

    Ids are visited in sorted order and both result tuples are ordered, so the same session
    produces byte-identical audit detail on every run — the same determinism the SELECTs this
    replaces got from their ``ORDER BY``.
    """
    by_fold = _vocabulary_by_fold(vocabulary)
    labels: set[str] = set()
    unrepresented: list[int] = []
    for category_id in sorted(set(category_ids)):
        code, name = category_code_by_id.get(category_id, (None, None))
        matched = _match_category_to_vocabulary(code, name, by_fold)
        if matched is None:
            unrepresented.append(category_id)
        else:
            labels.add(matched)
    return ItotApplicabilityContext(tuple(sorted(labels)), tuple(unrepresented), derived_from)


def resolve_scenario_itot_applicability(*, asset_category_id: int | None,
                                        involved_system_category_ids: Iterable[int] | None,
                                        session_category_ids: Iterable[int] | None,
                                        category_code_by_id: Mapping[int, tuple[Any, Any]],
                                        vocabulary: Iterable[str]) -> ItotApplicabilityContext:
    """The ITOT context for ONE scenario — its own systems first, the session's only as fallback.

    A session is the union of everything scoped into it; a scenario is usually about a corner of
    that. Deriving from the session for every scenario is what made an OT-specific scenario
    eligible for the whole IT control pool, so the scenario's OWN systems (its asset plus the
    supporting systems it names) win whenever it names any, and ``derived_from`` records which
    happened.

    ``category_code_by_id`` maps a ctm_scan_category id to its ``(code, name)`` pair — the same
    two columns ``grounding.resolve_asset_labels`` selects, because the name carries the
    parenthesised ``(CODE)`` marker that is the second matching door. A caller holding only codes
    passes ``(code, None)`` and simply loses that door.

    ``vocabulary`` is the label set the control library ACTUALLY carries. An empty one leaves
    every category unrepresented and the labels empty, which downstream means "demote nothing" —
    the same fail-open the shared resolver chose, for the same reason: a silently narrowed pool is
    the defect, an unfiltered one is merely less precise.
    """
    scenario_ids = set(involved_system_category_ids or ())
    if asset_category_id is not None:
        scenario_ids.add(asset_category_id)
    if scenario_ids:
        return _resolve_category_ids(scenario_ids, category_code_by_id, vocabulary, "scenario")
    session_ids = set(session_category_ids or ())
    if session_ids:
        return _resolve_category_ids(session_ids, category_code_by_id, vocabulary, "session")
    return ItotApplicabilityContext((), (), "none")


def resolve_scenario_security_domains(scored_domain_names: Iterable[tuple[str, float]],
                                      top_n: int) -> frozenset[str]:
    """The best ``top_n`` domain names out of already-scored ones. SELECTION ONLY.

    No embedding, no scoring, no IO: the caller has already decided how a domain scores (it owns
    the embedding client and the cache) and this decides only how many of them survive. Keeping
    the two apart is what lets the cut-off rule be tested without a model.

    A repeated domain keeps its best score, and ties break on the name so the returned set is a
    function of the input alone. ``top_n <= 0`` means "prefer nothing", which is a real
    configuration ("domain preference off"), not an error.
    """
    if top_n <= 0:
        return frozenset()
    best_by_name: dict[str, float] = {}
    for name, score in scored_domain_names:
        cleaned = _clean_text(name)
        if cleaned and (cleaned not in best_by_name or float(score) > best_by_name[cleaned]):
            best_by_name[cleaned] = float(score)
    ranked = sorted(best_by_name.items(), key=lambda pair: (-pair[1], pair[0]))
    return frozenset(name for name, _score in ranked[:top_n])


@dataclass(frozen=True)
class _RankedControlCandidate:
    """One deduped candidate reduced to the four things the ordering rule reads.

    The candidate's own row is deliberately dropped here: a map row carries the PK, the score and
    the rank and nothing else, so carrying the library row further would only invite a writer to
    persist a column the mapping table does not own.
    """

    control_library_id: Any
    score: float
    itot_demoted: bool
    domain_preferred: bool


@dataclass(frozen=True)
class ControlSelection:
    """What one scenario's selection decided, with the numbers that make it reviewable.

    ``mapped_count`` alone cannot tell "the library had exactly five good controls" apart from
    "the library had forty and the cap kept five" — which is why the old silent slice was a
    defect rather than a detail. Each count below answers one such question: how many cleared the
    cutoff at all, how many were borrowed from under it to reach the floor, how many cleared
    controls the ceiling threw away, how many were pushed down the order for being the wrong ITOT
    label, and how many below-cutoff candidates were left where they were.
    """

    rows: list[dict[str, Any]]
    cleared_cutoff_count: int
    mapped_count: int
    backfilled_count: int
    capped_count: int
    itot_demoted_count: int
    dropped_below_cutoff_count: int


def _rank_candidates(matches: Iterable[tuple[Mapping[str, Any], float]],
                     itot_context: ItotApplicabilityContext,
                     preferred_domains: Collection[str]) -> list[_RankedControlCandidate]:
    """Dedup by ControlLibraryID keeping the best score, and flag each survivor.

    THE DEDUP IS A GUARD, not tidiness: the map table's PK is (ScenarioID, ControlLibraryID), so
    one duplicate turns the whole batch insert into an IntegrityError — which the caller's
    ``except`` swallows into a single ``controls.mapping_failed`` WARNING, losing every control
    for that scenario over one repeated row.

    ``itot_demoted`` is False whenever the context has no labels (nothing to be incompatible
    WITH) or the control carries no ITOT label of its own (an unlabelled control applies
    everywhere, exactly as the unfiltered pool treats it). ``domain_preferred`` is recorded, never
    added to the score: a preference that touched the score could lift a control over the cutoff,
    and rule (d) is that domain must only ever reorder. Where it reorders is decided by the sort
    key in ``select_applicable_controls``, which now places it AFTER the score — see there for why
    a 97-value free-text vocabulary may break a tie and nothing more.
    """
    compatible = {label.casefold() for label in itot_context.labels}
    preferred = {fold for fold in (_clean_text(d).casefold() for d in preferred_domains) if fold}
    best: dict[Any, _RankedControlCandidate] = {}
    for row, score in matches:
        control_id = row.get("ControlLibraryID")
        numeric_score = float(score)   # builtin: a numpy float would fail the audit's json.dumps
        if control_id is None or (control_id in best and best[control_id].score >= numeric_score):
            continue
        label = _clean_text(row.get("ITOT")).casefold()
        best[control_id] = _RankedControlCandidate(
            control_library_id=control_id, score=numeric_score,
            itot_demoted=bool(compatible) and bool(label) and label not in compatible,
            domain_preferred=_clean_text(row.get("Domain")).casefold() in preferred)
    return list(best.values())


def _build_map_rows(candidates: Iterable[_RankedControlCandidate], *, scenario_id: str,
                    session_id: str, created_at: datetime) -> list[dict[str, Any]]:
    """Map rows in final order, MapRank stamped 1..n.

    ``created_at`` is passed in rather than read from a clock: every row of one pass must carry
    the same timestamp (they are one decision), and a function that reads the clock cannot be
    asserted on. ``SuggestedControl`` is deliberately not written — the column survives for legacy
    rows, but the model no longer proposes controls.
    """
    return [{"ScenarioID": scenario_id, "ControlLibraryID": candidate.control_library_id,
             "SessionID": session_id, "Score": candidate.score, "MapRank": rank,
             "CreatedAt": created_at}
            for rank, candidate in enumerate(candidates, start=1)]


def select_applicable_controls(*, scenario_id: str, session_id: str,
                               matches: Iterable[tuple[Mapping[str, Any], float]],
                               itot_context: ItotApplicabilityContext,
                               preferred_domains: Collection[str], min_score: float,
                               backfill_min_score: float, min_count: int, max_count: int,
                               created_at: datetime) -> ControlSelection:
    """THE ordering/cutoff/backfill/cap rule — one rule for both passes that used to have two.

    ``matches`` is (control row, score) best-first, as the reranker returned it. The rules, in
    order: dedup on the PK; split on ``min_score``; sort the cleared ones by (ITOT-demoted, score,
    domain-preferred); borrow from below the cutoff only to reach ``min_count`` and only above
    ``backfill_min_score``; then cap at ``max_count``.

    THE SORT KEY'S ORDER IS THE RULE, and DOMAIN NOW SITS AFTER SCORE. It used to sit before it —
    ``(itot_demoted, not domain_preferred, -score)`` — which SUPERSEDES the claim written above
    rule (d) below that "domain must only ever reorder": placed there it did not break ties, it
    outranked the score outright, so a control in a preferred domain beat a materially better
    match. Domain is the weakest signal in this whole funnel: ``Control_Library.Domain`` is an
    un-normalized 97-value free-text vocabulary that models.py and schemas.py both document as
    "reported as-is, never joined on", and the preference itself is derived from a cosine between
    that free text and the query, not from anything curated. A signal that weak may break a tie
    and nothing more. ITOT stays the PRIMARY key deliberately: a control compatible with the
    scenario's own IT/OT nature must outrank an incompatible one whatever either scored, because
    an incompatible control is not a worse answer to the question — it is an answer to a different
    one.

    THIS IS THE ONLY PLACE MAP ORDER IS DECIDED, for both passes and for a top-up merging its new
    rows into a scenario's existing ones. ``control_mapping.renumber_map_ranks_by_score`` used to
    re-derive MapRank for a topped-up scenario from Score ALONE afterwards, which silently
    discarded both the ITOT demotion and the domain tie-break this function had just applied — the
    demotion that the per-scenario ITOT context exists to produce. That function is deleted rather
    than corrected: a second ordering implementation is the defect, and a correct second one would
    only be a defect waiting to drift back.

    ``min_count`` is a FLOOR and ``max_count`` a CEILING, and conflating them is how the two
    old implementations disagreed: generation sliced at ``control_map_top_k`` with no floor, so a
    scenario could be planned against one control, while the top-up filled to
    ``remediation_control_min_count`` with NO cutoff at all, so it could write a nearest-match
    control scoring 3. Here the floor may only be reached from candidates above
    ``backfill_min_score`` — if that cannot reach it, the selection comes back short rather than
    padded, because an arbitrary control is worse than a missing one on a remediation plan.

    ITOT never DROPS a control (a mislabeled library row must not make a good control unreachable)
    — it only sorts it behind every compatible one, where the cap is what finally decides. Domain
    preference is a sort key only: it cannot admit anything that did not clear the cutoff.
    """
    candidates = _rank_candidates(matches, itot_context, preferred_domains)
    cleared = sorted((c for c in candidates if c.score >= min_score),
                     key=lambda c: (c.itot_demoted, -c.score, not c.domain_preferred,
                                    str(c.control_library_id)))
    below = sorted((c for c in candidates if c.score < min_score),
                   key=lambda c: (c.itot_demoted, -c.score, str(c.control_library_id)))
    shortfall = max(0, min_count - len(cleared))
    backfill = [c for c in below if c.score >= backfill_min_score][:shortfall]
    kept = (cleared + backfill)[:max(0, max_count)]
    backfilled_count = max(0, len(kept) - len(cleared))
    return ControlSelection(
        rows=_build_map_rows(kept, scenario_id=scenario_id, session_id=session_id,
                             created_at=created_at),
        cleared_cutoff_count=len(cleared), mapped_count=len(kept),
        backfilled_count=backfilled_count,
        capped_count=max(0, len(cleared) - max(0, max_count)),
        itot_demoted_count=sum(1 for c in cleared if c.itot_demoted),
        dropped_below_cutoff_count=len(below) - backfilled_count)


def _raise_on_corrupt_rows(rows: list[dict[str, Any]], candidate_ids: Collection[Any]) -> None:
    """The checks that must stop the write: an unknown id, a duplicate id, a broken rank run.

    RAISING is the point. The caller maps inside a savepoint, so an exception rolls the mapping
    back and leaves the scenario unstamped for the retry sweep — whereas a warning would be
    logged and the row written anyway. Each of these three means the batch no longer describes
    what was actually matched: an id outside the candidate set was never scored against this
    scenario, a duplicate is the IntegrityError that loses the whole batch, and a rank run with a
    hole breaks the published "MapRank 1 = best match" contract every surface renders.
    """
    known = set(candidate_ids)
    seen: set[Any] = set()
    for row in rows:
        control_id = row.get("ControlLibraryID")
        if control_id not in known:
            raise ValueError(f"control {control_id!r} is not among the {len(known)} candidates "
                             "scored for this scenario")
        if control_id in seen:
            raise ValueError(f"control {control_id!r} appears twice — the map PK is "
                             "(ScenarioID, ControlLibraryID) and the insert would lose the batch")
        seen.add(control_id)
    ranks = sorted(row.get("MapRank") or 0 for row in rows)
    if ranks != list(range(1, len(rows) + 1)):
        raise ValueError(f"MapRank must run 1..{len(rows)} with no gaps, got {ranks}")


def validate_control_mapping(*, rows: list[dict[str, Any]], candidate_ids: Collection[Any],
                             itot_context: ItotApplicabilityContext, backfill_min_score: float,
                             itot_by_control_id: Mapping[Any, Any] | None,
                             expected_count: int | None) -> list[str]:
    """Pre-persist check: raise on corruption, RETURN the advisories.

    The split is deliberate and matches what the caller can do about each. Corruption (see
    ``_raise_on_corrupt_rows``) means the batch is wrong and must not be written — the caller's
    savepoint turns that into "this scenario stays queued". An advisory means the batch is the
    best available answer and SHOULD be written, but the fact that it is thin, borrowed from under
    the floor, or ITOT-incompatible belongs in the audit row beside it; swallowing those is how a
    degraded run became indistinguishable from a clean one.

    ``itot_by_control_id`` (id -> ITOT label) and ``expected_count`` are facts only the CALLER
    holds — a map row carries no ITOT label, and only the caller knows what count it was aiming
    for. They are REQUIRED keywords with no default, deliberately: each one gates an advisory, so
    a default would let a caller skip two of the three checks and still get back ``[]`` — byte
    identical to a batch that was fully checked and clean. Passing ``None`` is allowed and means
    "I do not have this fact", but it has to be said out loud at the call site rather than
    happening by omission. That is the same reason ControlMatches separates "no verdict" from
    "nothing matched": an unchecked result must never read as a clean one.
    """
    _raise_on_corrupt_rows(rows, candidate_ids)
    compatible = {label.casefold() for label in itot_context.labels}
    labels = itot_by_control_id or {}
    warnings: list[str] = []
    for row in rows:
        control_id = row.get("ControlLibraryID")
        score = float(row.get("Score") or 0.0)
        if score < backfill_min_score:
            warnings.append(f"control {control_id!r} scored {score:.2f}, below the backfill floor "
                            f"{backfill_min_score:.2f}")
        label = _clean_text(labels.get(control_id)).casefold()
        if compatible and label and label not in compatible:
            warnings.append(f"control {control_id!r} is labelled "
                            f"{_clean_text(labels.get(control_id))!r}, outside this scenario's "
                            f"ITOT context {list(itot_context.labels)}")
    if expected_count is not None and len(rows) < expected_count:
        warnings.append(f"mapped {len(rows)} controls, fewer than the {expected_count} expected")
    return warnings
