# Pure re-export of passagemath's split sage.all modules. No numeric patches.
from sage.all__sagemath_modules import *  # noqa: F401,F403
from sage.all__sagemath_categories import *  # noqa: F401,F403
from sage.all__sagemath_flint import *  # noqa: F401,F403
from sage.all__sagemath_symbolics import *  # noqa: F401,F403


def line(*a, **k):  # plotting only (simulator.py); not used by any cost computation
    raise NotImplementedError("plotting not installed")
