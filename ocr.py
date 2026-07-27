import os
import logging
# Enforce absolute offline state
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

import fitz  # PyMuPDF
import torch
from transformers import pipeline

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

LOCAL_MODEL_PATH = "/home/user/secure-models/unlimited-ocr"

def load_ocr_pipeline():
    """Initializes the pipeline locally with zero network calls."""
    logging.info("Loading local Unlimited-OCR model into memory...")
    return pipeline(
        "image-text-to-text", 
        model=LOCAL_MODEL_PATH, 
        trust_remote_code=True,
        device_map="auto"
    )

def process_pdf_to_markdown(pdf_path, output_txt_path, ocr_pipe):
    """Converts PDF pages to images in-memory and processes them via local OCR."""
    try:
        # Open the PDF securely from local storage
        doc = fitz.open(pdf_path)
        full_markdown = []
        
        logging.info(f"Opened PDF: {pdf_path} ({len(doc)} pages)")
        
        for page_num in range(len(doc)):
            logging.info(f"Processing page {page_num + 1}/{len(doc)}...")
            page = doc.load_page(page_num)
            
            # Render page to a high-resolution image matrix (300 DPI for crisp OCR)
            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
            
            # Convert the raw pixel data directly into an in-memory byte buffer (PNG format)
            # This ensures no unencrypted PHI/PII images are written to your laptop's hard drive
            image_bytes = pix.tobytes("png")
            
            # Run the OCR model using the byte stream
            prompt = "Convert this medical document page into structured markdown. Maintain formatting precisely."
            result = ocr_pipe(prompt, [image_bytes])
            
            # Append results with structural page markers
            full_markdown.append(f"\n\n<!-- PAGE {page_num + 1} -->\n\n")
            
            # Handle standard transformers pipeline dictionary structure output safely
            if isinstance(result, list) and len(result) > 0:
                extracted_text = result[0].get("generated_text", str(result[0]))
                full_markdown.append(extracted_text)
            else:
                full_markdown.append(str(result))
                
        # Write the final consolidated markdown file locally
        with open(output_txt_path, "w", encoding="utf-8") as f:
            f.write("".join(full_markdown))
            
        logging.info(f"Successfully saved extracted clinical markdown to: {output_txt_path}")
        
    except Exception as e:
        logging.error(f"Failed to process PDF secure pipeline: {str(e)}")

if __name__ == "__main__":
    # Initialize the model once
    ocr_pipe = load_ocr_pipeline()
    
    # Define local system filepaths
    INPUT_PDF = "/home/user/secure_data/patient_chart.pdf"
    OUTPUT_TEXT = "/home/user/secure_data/patient_chart_extracted.md"
    
    process_pdf_to_markdown(INPUT_PDF, OUTPUT_TEXT, ocr_pipe)
