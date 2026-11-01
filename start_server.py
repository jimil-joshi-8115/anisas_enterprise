import sys
import os
_here = os.path.dirname(os.path.abspath(__file__))
_svc = os.path.join(_here, "ai-service")
os.chdir(_svc)
sys.path.insert(0, _svc)
import uvicorn
import main
uvicorn.run(main.app, host="0.0.0.0", port=int(os.getenv("PORT", 9000)))
