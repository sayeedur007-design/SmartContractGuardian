# ==============================
# File: rag/doc_db.py
# ==============================
import os
import json
import pinecone
from dotenv import load_dotenv
from pathlib import Path

from langchain.docstore.document import Document
from langchain_openai import OpenAIEmbeddings
from langchain.text_splitter import TokenTextSplitter
from langchain_community.vectorstores import Pinecone

from utils.print_utils import create_progress_bar, print_step

load_dotenv()


def init_pinecone_index(index_name: str = "auditme"):
    """
    Initialize Pinecone, create index if it doesn't exist.
    By default, uses environment variables:
      - PINECONE_API_KEY
      - PINECONE_ENV
    """
    pc = pinecone.Pinecone(
        api_key=os.getenv("PINECONE_API_KEY"), environment=os.getenv("PINECONE_ENV")
    )

    if index_name not in pc.list_indexes().names():
        pc.create_index(
            name=index_name,
            metric="cosine",
            dimension=1536,
            spec=pinecone.ServerlessSpec(cloud="aws", region="us-east-1"),
        )


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
            "start_line": str(start_line),  # Convert to string
            "end_line": str(end_line),  # Convert to string
            "vuln_lines": [
                str(line) for line in chunk_vuln_lines
            ],  # Convert each line number to string
            "vuln_categories": list(chunk_vuln_cats),  # Categories are already strings
        }

        doc = Document(page_content=cleaned_text, metadata=metadata)
        documents.append(doc)

    return documents


def build_pinecone_vectorstore_from_json(
    json_path: str, base_dataset_dir: str, index_name: str = "auditme"
):
    """
    1) Parse the JSON describing vulnerabilities
    2) For each contract, read its .sol file from disk
    3) Chunk it + attach vulnerability metadata
    4) Build the Pinecone index with these Documents (only if the index is empty)
    5) Return the VectorStore
    """
    # Ensure Pinecone index is set up
    print_step("Initializing Pinecone...")
    init_pinecone_index(index_name=index_name)

    # Initialize Pinecone client
    pc = pinecone.Pinecone(
        api_key=os.getenv("PINECONE_API_KEY"), environment=os.getenv("PINECONE_ENV")
    )
    index = pc.Index(index_name)

    # Check if the index is empty
    index_stats = index.describe_index_stats()
    if index_stats["total_vector_count"] > 0:
        print("Index already contains data. Skipping document upload.")
        return Pinecone.from_existing_index(
            index_name=index_name,
            embedding=OpenAIEmbeddings(openai_api_key=os.getenv("OPENAI_API_KEY")),
        )

    # If the index is empty, proceed with document upload
    vuln_data = load_json_vulns(json_path)
    all_docs = []

    with create_progress_bar("Processing contracts") as progress:
        task = progress.add_task("Processing...", total=len(vuln_data))

        for cdata in vuln_data:
            full_path = os.path.join(base_dataset_dir, cdata["path"])
            if not os.path.isfile(full_path):
                print(f"Warning: File not found: {full_path}. Skipping.")
                continue

            # Load the entire .sol contract
            with open(full_path, "r", encoding="utf-8") as f:
                sol_code = f.read()

            # Build a line->categories map
            line_vulns_map = {}
            for vuln_item in cdata.get("vulnerabilities", []):
                cat = vuln_item["category"]
                for ln in vuln_item["lines"]:
                    line_vulns_map.setdefault(ln, []).append(cat)

            # Create chunked Documents
            doc_list = chunk_contract_with_metadata(
                sol_code,
                line_vulns_map,
                filename=cdata.get("name", ""),
                pragma=cdata.get("pragma", ""),
                source=cdata.get("source", ""),
            )

            all_docs.extend(doc_list)
            progress.update(task, advance=1)

    print(f"Total chunked documents: {len(all_docs)}")
    print_step(f"Uploading {len(all_docs)} documents to Pinecone...")

    # Create embeddings
    embeddings = OpenAIEmbeddings(openai_api_key=os.getenv("OPENAI_API_KEY"))

    # Upload documents to the index
    vectorstore = Pinecone.from_documents(all_docs, embeddings, index_name=index_name)
    return vectorstore


def get_vuln_retriever_from_json(
    json_path: str, base_dataset_dir: str, index_name: str = "auditme", top_k: int = 5
):
    """
    Builds (or updates) the Pinecone index from your JSON-based vulnerability data,
    and returns a retriever for that index.
    """
    vectorstore = build_pinecone_vectorstore_from_json(
        json_path=json_path, base_dataset_dir=base_dataset_dir, index_name=index_name
    )
    retriever = vectorstore.as_retriever(search_kwargs={"k": top_k})
    return retriever
