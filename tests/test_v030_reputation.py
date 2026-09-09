from sentinel.reputation import ReputationEngine

def test_allowlisted_file_is_locally_trusted(tmp_path):
    from sentinel.database import Database
    db=Database(tmp_path/"db.sqlite")
    p=tmp_path/"app.exe"
    p.write_bytes(b"MZ harmless test")
    db.add_allowlist("file",str(p))
    engine=ReputationEngine(db)
    result=engine.assess_file(p,"abc",base_score=0)
    assert result.local_trust=="allowlisted"
    assert result.score_delta==0

def test_invalid_signature_adds_context(tmp_path,monkeypatch):
    from sentinel.database import Database
    db=Database(tmp_path/"db.sqlite")
    p=tmp_path/"sample.exe"
    p.write_bytes(b"MZ harmless test")
    engine=ReputationEngine(db)
    monkeypatch.setattr(engine,"_authenticode",lambda path:("HashMismatch","CN=Test"))
    result=engine.assess_file(p,"abc",base_score=20,force_signature=True)
    assert result.score_delta>=10
    assert any("non valida" in x.lower() for x in result.reasons)

def test_reputation_cache_avoids_second_signature_query(tmp_path,monkeypatch):
    from sentinel.database import Database
    db=Database(tmp_path/"db.sqlite")
    p=tmp_path/"sample.exe"
    p.write_bytes(b"MZ harmless test")
    engine=ReputationEngine(db)
    calls={"n":0}
    def sig(path):
        calls["n"]+=1
        return "Valid","CN=Trusted"
    monkeypatch.setattr(engine,"_authenticode",sig)
    engine.assess_file(p,"abc",base_score=20,force_signature=True)
    second=engine.assess_file(p,"abc",base_score=20,force_signature=True)
    assert calls["n"]==1
    assert second.cached
