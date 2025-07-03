# Ingestor ETL – Open Source Version

**Ingestor ETL** is an open source Python-based tool developed by **PAiCore Technologies**. It enables the parsing and ingestion of network trace files (*PCAP/PCAPNG*) for various telecom protocols into a **PostgreSQL** database.

This repository is designed for educational and community-driven collaboration, demonstrating how to handle the ETL (Extract, Transform, Load) process for telecom network data.

---

## Features

- 🚀 **Protocol Support**: GTP, SIP, CAP, HTTP, SMPP, Diameter, and SS7
- 📂 **Database Integration**: Scalable PostgreSQL storage
- 🔄 **Modular Architecture**: Extensible and maintainable codebase
- 📡 **Telecom Focus**: Specialized handling for Diameter (AAA) and SS7 networks

---

## What’s Included

- 🐍 **Python scripts** for parsing Diameter, GTP, SIP, SMPP, HTTP, GSM MAP, and other protocols.
- 🗄️ Example **PostgreSQL configuration** to store parsed data.
- 📄 Example `config.py` and `requirements.txt`.

---

## Prerequisites

- **Python 3.8+**
- **PostgreSQL** (local or remote)
- Recommended OS: **Ubuntu 22.04** or similar

> 💡 Ensure PostgreSQL allows remote connections and has proper user permissions

---

## Install Dependencies

1. Create virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

**Key Dependencies**:  
`dpkt`, `pycrate`, `smpppdu`, `SQLAlchemy`, `psycopg2`, `xmltodict`

---

## Database Setup

**Step 1:** Create two databases:
- `nbm` → Raw trace storage.
- `ingestion` → Parsed and processed data.

**Step 2:** Create a PostgreSQL user with appropriate privileges.

**Example connection (`config.py`):**

```python
class Settings():
    DB_HOSTNAME: str = "127.0.0.1"
    DB_PORT: str = "5432"
    DB_NAME: str = "nbm"
    DB_USERNAME: str = "your_username"
    DB_PASSWORD: str = "your_password"

settings = Settings()
```

---

## Usage
Run protocol-specific ingestors:

```bash
python diameter.py   # Diameter protocol
# python gtp.py     # GTP protocol
# python sip.py     # SIP protocol
```

> Always verify credentials in `config.py` before execution

---

## Best Practices

- Use virtual environments for dependency isolation
- Store credentials securely (never hardcode)
- Start with small PCAP samples for testing
- Monitor database performance with large volumes

---

## Contributing

Community contributions are welcome!  
Please feel free to fork this repo, open issues, or submit pull requests for improvements or additional protocol support.

---

## Contact & Support
This open source version is maintained by the PAiCore Technologies team and the community.  
For commercial support, enterprise deployments, or custom solutions, please contact us at:

🌐 [https://paicore.tech](https://paicore.tech)
