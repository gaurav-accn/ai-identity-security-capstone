
import re
from pathlib import Path
from collections import Counter


# ==================================================
# CONFIGURATION
# ==================================================
# Point the retriever at the local knowledge-base directory so each retrieval test uses the same text corpus.

RAG_DOCS_DIR = Path("rag_docs")

STOP_WORDS = {
    "the", "is", "are", "a", "an", "and",
    "or", "to", "of", "in", "on", "for",
    "can", "i", "my", "me", "what", "how",
    "when", "where", "does", "do", "your",
    "please", "tell", "about"
}


# ==================================================
# TEXT PROCESSING
# ==================================================
# Normalize each document and question into lower-case tokens so relevance scoring compares the same terms consistently.

def tokenize(text):
    """
    Convert text into lowercase words and remove
    common English stop words.
    """

    words = re.findall(r"\b[a-z0-9]+\b", text.lower())

    filtered_words = [
        word for word in words
        if word not in STOP_WORDS
    ]

    return filtered_words


# ==================================================
# LOAD KNOWLEDGE BASE
# ==================================================
# Read every text file in the doc directory and package each one as a document object for later retrieval.

def load_documents():

    documents = []

    if not RAG_DOCS_DIR.exists():
        raise FileNotFoundError(
            f"Knowledge base not found: {RAG_DOCS_DIR}"
        )

    for file_path in sorted(RAG_DOCS_DIR.glob("*.txt")):

        content = file_path.read_text(
            encoding="utf-8"
        ).strip()

        if content:

            documents.append({
                "filename": file_path.name,
                "content": content
            })

    return documents


# ==================================================
# RETRIEVAL
# ==================================================
# Score each document by keyword overlap and return the most relevant subset for the prompt.

def retrieve_documents(question, top_k=2):

    documents = load_documents()

    question_words = tokenize(question)

    scored_documents = []

    for document in documents:

        document_words = tokenize(
            document["content"]
        )

        word_counts = Counter(document_words)

        score = sum(
            word_counts[word]
            for word in question_words
        )

        scored_documents.append({
            "filename": document["filename"],
            "content": document["content"],
            "score": score
        })

    # Sort by relevance score, highest first.
    scored_documents.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    # Return only documents with a positive score.
    relevant_documents = [
        document
        for document in scored_documents
        if document["score"] > 0
    ]

    return relevant_documents[:top_k]


# ==================================================
# TEST RETRIEVAL
# ==================================================
# Run a few sample questions to confirm the retriever returns the expected support and account knowledge.

if __name__ == "__main__":

    test_questions = [
        "How can I request a refund?",
        "What are the customer support hours?",
        "How do I reset my password?"
    ]

    for question in test_questions:

        print("\n" + "=" * 70)
        print("USER QUESTION:")
        print(question)

        retrieved = retrieve_documents(question)

        print("\nRETRIEVED DOCUMENTS:")

        if not retrieved:
            print("No relevant documents found.")

        for document in retrieved:

            print(
                f"\nFile: {document['filename']}"
            )

            print(
                f"Relevance score: {document['score']}"
            )

            print("\nContent:")
            print(document["content"])
