# SecureByDesign: Automated Threat Modeling with LLMs

**SecureByDesign** is an end-to-end AI pipeline that automates STRIDE threat modeling. It parses system architecture Data Flow Diagrams (DFDs) and uses Large Language Models (LLMs) to automatically detect and infer potential security threats. 

This is a mini-project that was built to address the time-consuming and manual nature of traditional threat modeling by bringing cutting-edge LLMs directly into the architecture design phase.

## Features
- **Intelligent Parsing:** Parses unstructured DFDs into structured security contexts.
- **LLM Threat Inference:** Integrates with the Groq API (Llama 3 8B/70B) to reliably construct detailed STRIDE threat reports.
- **Automated Evaluation Harness:** Includes a rigorous testing suite (`evaluate.py`) that benchmarks Precision, Recall, and F1-score against the *microSecEnD* dataset.
- **Interactive UI:** A Streamlit-based web application for real-time, interactive threat modeling.

## Project Structure
- `SecureByDesign/pipeline/`: Contains the DFD parsing and LLM inference engine.
- `SecureByDesign/evaluation/`: Contains the automated test suite and ground truth generators.
- `streamlit_app_premium.py`: The Streamlit web interface.
- Jupyter Notebooks: Documents the step-by-step process of building and testing the system.

## Setup & Evaluation 
1. Install dependencies:
   ```bash
   pip install -r SecureByDesign/requirements.txt
   ```
2. Export your Groq API key:
   ```bash
   export GROQ_API_KEY="your_api_key_here"
   ```
3. Run the evaluation harness to see the models' precision and recall on the dataset:
   ```bash
   python -m SecureByDesign.evaluation.evaluate
   ```

*Note: This repository represents a full Software Engineering project lifecycle from dataset preparation to LLM inference and rigorous evaluation.*
