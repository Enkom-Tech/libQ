import sys, types
import sage.all__sagemath_symbolics as m
import sage.all__sagemath_modules as m2
a = types.ModuleType("sage.all")
for mod in (m2, m):
    for k in dir(mod):
        if not k.startswith("__"): setattr(a, k, getattr(mod, k))
sys.modules["sage.all"] = a
import sage; sage.all = a
a.line = lambda *x, **k: None
