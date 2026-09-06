"""Row visibility is the CALLER's declaration, not a constant baked into the DAL.

dal.upsert_threat_type / upsert_threat_catalogue used to hardcode IsActive=False. That is right
for their AI-promotion caller (pending curator review) and wrong for a curated bulk import — and
because grounding.get_possible_types / get_possible_names / embeddings._catalogue_texts all filter
IsActive == True, an import that inherited the default added rows retrieval could NEVER return
while reporting success. The old workaround was for each such caller to UPDATE the rows back on
afterwards, which every future caller had to remember.

These tests pin the fix at its cause: `is_active` is an argument, the default preserves the
promotion path byte-for-byte, and an EXISTING row's visibility is never rewritten.
"""
from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import dal
from app.db import models as m


def _session():
    engine = create_engine("sqlite://")
    m.Threat_Type.__table__.create(engine)
    m.Threat_Catalogue.__table__.create(engine)
    return sessionmaker(bind=engine)()


def _type_active(sess, type_id):
    return sess.execute(select(m.Threat_Type.IsActive)
                        .where(m.Threat_Type.ThreatTypeID == type_id)).scalar()


def _cat_active(sess, cat_id):
    return sess.execute(select(m.Threat_Catalogue.IsActive)
                        .where(m.Threat_Catalogue.ThreatCatalogueID == cat_id)).scalar()


def test_default_still_inserts_pending_so_the_promotion_path_is_unchanged():
    """The default MUST stay False: promote.py relies on an AI-promoted row being invisible to
    grounding until a curator approves it."""
    sess = _session()
    type_id, created = dal.upsert_threat_type(sess, "AI Promoted Type", None)
    cat_id, _ = dal.upsert_threat_catalogue(sess, "AI Promoted Threat", type_id)
    assert created is True
    assert _type_active(sess, type_id) is False
    assert _cat_active(sess, cat_id) is False


def test_curated_import_rows_are_born_visible():
    """The root-cause fix: a curated import declares is_active=True at the INSERT, so the row is
    never briefly invisible and needs no follow-up UPDATE."""
    sess = _session()
    type_id, _ = dal.upsert_threat_type(sess, "Embedded Device - Hardware", None,
                                        source="mitre_emb3d", is_active=True)
    cat_id, _ = dal.upsert_threat_catalogue(sess, "TID-108 Firmware modified undetected", type_id,
                                            source="mitre_emb3d", is_active=True)
    assert _type_active(sess, type_id) is True
    assert _cat_active(sess, cat_id) is True


def test_an_existing_pending_row_is_never_flipped_live_by_a_later_import():
    """First-writer, and it must hold for VISIBILITY too.

    A curator may have deliberately left (or made) a row pending. An import that later references
    the same name must reuse it, not publish it — which is exactly the bug a blanket
    `UPDATE ... WHERE Source IN (...)` reactivation would have introduced."""
    sess = _session()
    pending_id, created = dal.upsert_threat_type(sess, "Contested Name", None)   # default: pending
    assert created is True and _type_active(sess, pending_id) is False

    same_id, created_again = dal.upsert_threat_type(sess, "Contested Name", None,
                                                    source="pytm", is_active=True)
    assert same_id == pending_id, "must reuse the existing row, not mint a second"
    assert created_again is False
    assert _type_active(sess, pending_id) is False, "an existing row keeps its own visibility"


def test_catalogue_upsert_does_not_dedup_on_its_own_so_the_caller_must():
    """upsert_threat_catalogue only MINTS -- its docstring puts the normalized-name dedup on the
    caller (find_catalogue_id_by_norm_name, type-scoped). With no unique index present it happily
    inserts a twin, which is why app/intel/library_import.import_records pre-loads the natural
    keys instead of relying on the IntegrityError recovery branch."""
    sess = _session()
    type_id, _ = dal.upsert_threat_type(sess, "T", None, is_active=True)
    first_id, _ = dal.upsert_threat_catalogue(sess, "Shared Threat Name", type_id)
    second_id, created = dal.upsert_threat_catalogue(sess, "Shared Threat Name", type_id,
                                                    source="pytm", is_active=True)
    assert (second_id, created) != (first_id, False), "no self-dedup: caller owns it"
    assert _cat_active(sess, first_id) is False, "the pre-existing row is untouched"
