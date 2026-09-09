import time
from sentinel.correlation import FileProcessCorrelator

def test_exact_attribution():
    c=FileProcessCorrelator(); c.record(r"C:\\Users\\A\\x.txt",42,"writer.exe",r"C:\\Temp\\writer.exe")
    a=c.attribute(r"C:\\Users\\A\\x.txt"); assert a.pid==42 and a.available

def test_stale_not_attributed():
    c=FileProcessCorrelator(); c.record(r"C:\\x.txt",1,"x.exe",ts=time.time()-20)
    assert not c.attribute(r"C:\\x.txt",2).available
