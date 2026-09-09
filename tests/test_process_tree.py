from sentinel.process_tree import ProcessTree

def test_process_tree_ancestry():
    t=ProcessTree(); t.observe(1,0,"explorer.exe"); t.observe(10,1,"winword.exe"); t.observe(20,10,"powershell.exe")
    assert [n.pid for n in t.ancestry(20)]==[20,10,1]
    assert t.describe_chain(20)=="explorer.exe → winword.exe → powershell.exe"
