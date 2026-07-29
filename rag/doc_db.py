# ==============================
# File: rag/doc_db.py
# ==============================
import os
import json
from dotenv import load_dotenv
from pathlib import Path

from langchain.docstore.document import Document
from langchain.text_splitter import TokenTextSplitter


from utils.print_utils import create_progress_bar, print_step

load_dotenv()





def load_json_vulns(json_path: str) -> list:
    """
    Loads your JSON file, which is an array of objects with:
      - name
      - path
      - pragma
      - source
      - vulnerabilities: [ { "lines": [...], "category": ... }, ... ]
    Returns a list of dicts.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def chunk_contract_with_metadata(
    full_text: str, line_vulns: dict, filename: str, pragma: str = "", source: str = ""
) -> list:
    """
    Splits the contract text into token-based chunks (using TokenTextSplitter),
    while preserving line info & vulnerability metadata in Document.metadata.

    :param full_text: The entire Solidity code as a single string
    :param line_vulns: A dict mapping lineNumber -> [categories], e.g.
                       {31: ["access_control"], 38: ["access_control"]}
    :param filename: "FibonacciBalance.sol"
    :param pragma: e.g. "0.4.22"
    :param source: e.g. "https://github.com/..."
    :return: A list of langchain Document objects
    """
    lines = full_text.split("\n")

    # Insert <LINE=X> markers so we can backtrack line numbers after chunking
    labeled_lines = []
    for i, line in enumerate(lines, start=1):
        labeled_lines.append(f"<LINE={i}>{line}")
    labeled_text = "\n".join(labeled_lines)

    # Token-based splitting
    splitter = TokenTextSplitter(chunk_size=1024, chunk_overlap=0)
    chunks = splitter.split_text(labeled_text)

    documents = []
    for chunk in chunks:
        # Parse out the line numbers that appear in this chunk
        line_nums_in_chunk = []
        for c_line in chunk.split("\n"):
            if c_line.startswith("<LINE="):
                try:
                    # e.g. "<LINE=31>"
                    line_num_str = c_line.split(">", 1)[0].replace("<LINE=", "")
                    line_num = int(line_num_str)
                    line_nums_in_chunk.append(line_num)
                except:
                    pass

        if not line_nums_in_chunk:
            # If for some reason it's an empty chunk
            continue

        start_line = min(line_nums_in_chunk)
        end_line = max(line_nums_in_chunk)

        # Remove the <LINE=..> markers from the content
        cleaned_lines = []
        for c_line in chunk.split("\n"):
            if c_line.startswith("<LINE="):
                try:
                    idx = c_line.index(">")
                    c_line = c_line[idx + 1 :]  # everything after the '>'
                except ValueError:
                    # If ">" is not found, keep the line as is
                    print(f"Warning: Malformed line marker in {filename}: {c_line}")
                    pass
            cleaned_lines.append(c_line)
        cleaned_text = "\n".join(cleaned_lines)

        # Collect vulnerabilities for lines in [start_line, end_line]
        chunk_vuln_lines = []
        chunk_vuln_cats = set()
        for ln in range(start_line, end_line + 1):
            if ln in line_vulns:
                chunk_vuln_lines.append(ln)
                for cat in line_vulns[ln]:
                    chunk_vuln_cats.add(cat)

        metadata = {
            "filename": filename,
            "pragma": pragma,
            "source": source,
            "start_line": start_line,
            "end_line": end_line,
            "vuln_lines": ",".join(map(str, chunk_vuln_lines)),
            "vuln_categories": ",".join(sorted(chunk_vuln_cats)),
        }

        doc = Document(page_content=cleaned_text, metadata=metadata)
        documents.append(doc)

    return documents

def build_chroma_vectorstore_from_json(
    
    json_path: str,
    base_dataset_dir: str,
    persist_directory: str = "./chroma_db",
):
    """
        Builds a local Chroma vector database from the vulnerability dataset.
        If the database already exists, it is reused.
    """
    
    from langchain_chroma import Chroma
    from langchain_ollama import OllamaEmbeddings
    from chromadb.config import Settings
   

    print_step("Initializing Local ChromaDB...")

    try:
        embeddings = OllamaEmbeddings(
            model="nomic-embed-text"
            base_url="http://127.0.0.1:11434"
        )

        vectorstore = Chroma(
            persist_directory=persist_directory,
            embedding_function=embeddings,
            client_settings=Settings(anonymized_telemetry=False),
        )
    except Exception as e:
        print_step(f"Failed to initialize ChromaDB: {e}")
        return None

    try:
        existing = vectorstore.get()

        if existing and len(existing["ids"]) > 0:
            print_step(
                f"Loaded existing Chroma database with {len(existing['ids'])} vectors."
            )
            return vectorstore

    except Exception:
        pass

    vuln_data = load_json_vulns(json_path)

    all_docs = []

    with create_progress_bar("Processing contracts") as progress:

        task = progress.add_task(
            "Processing...",
            total=len(vuln_data),
        )

        for cdata in vuln_data:

            full_path = os.path.join(
                base_dataset_dir,
                cdata["path"],
            )

            if not os.path.isfile(full_path):
                print(f"Warning: File not found: {full_path}")
                progress.update(task, advance=1)
                continue

            with open(full_path, "r", encoding="utf-8") as f:
                source = f.read()

            line_vulns = {}

            for vuln in cdata.get("vulnerabilities", []):

                category = vuln["category"]

                for line in vuln["lines"]:
                    line_vulns.setdefault(line, []).append(category)

            docs = chunk_contract_with_metadata(
                source,
                line_vulns,
                filename=cdata.get("name", ""),
                pragma=cdata.get("pragma", ""),
                source=cdata.get("source", ""),
            )

            all_docs.extend(docs)

            progress.update(task, advance=1)

    print_step(f"Embedding {len(all_docs)} chunks...")

# Ensure metadata contains only Chroma-supported types
    for doc in all_docs:
        cleaned_metadata = {}
        for key, value in doc.metadata.items():
            if isinstance(value, list):
                cleaned_metadata[key] = ",".join(map(str, value))
            elif isinstance(value, dict):
                cleaned_metadata[key] = json.dumps(value)
            else:
                cleaned_metadata[key] = value
        doc.metadata = cleaned_metadata

    try:
        vectorstore.add_documents(all_docs)

    except Exception as e:
        print_step(f"Failed to add documents to ChromaDB: {e}")
        return None

    print_step("Local ChromaDB created successfully.")

    return vectorstore


def get_vuln_retriever_from_json(
    json_path: str,
    base_dataset_dir: str,
    persist_directory: str = "./chroma_db",
    top_k: int = 5,
):

    vectorstore = build_chroma_vectorstore_from_json(
        json_path=json_path,
        base_dataset_dir=base_dataset_dir,
        persist_directory=persist_directory,
    )

    if vectorstore is None:
        print_step("RAG retriever unavailable.")
        return None

    return vectorstore.as_retriever(
        search_kwargs={
            "k": top_k
        }
    )
