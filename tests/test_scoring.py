from sentinel.scoring import Signal, assess, level_for

def test_levels():
    assert level_for(0) == "SAFE"
    assert level_for(25) == "LOW"
    assert level_for(50) == "SUSPICIOUS"
    assert level_for(70) == "HIGH"
    assert level_for(85) == "CRITICAL"

def test_cap_and_diminishing():
    a=assess([Signal("x",80,"a"),Signal("x",80,"b"),Signal("y",30,"c")])
    assert a.score == 100
