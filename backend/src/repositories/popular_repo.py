import pandas as pd
from pathlib import Path

class PopularDomainRepository:
    def __init__(self, filename="popular_domains.csv"):
        # Get backend/ directory
        base_dir = Path(__file__).resolve().parents[2]
        data_path = base_dir / "data" / filename

        if not data_path.exists():
            raise FileNotFoundError(f"Popular domains file not found: {data_path}")

        df = pd.read_csv(data_path, header=None, names=["domain"])
        self.domains = set(df["domain"].astype(str).str.lower().str.strip())
