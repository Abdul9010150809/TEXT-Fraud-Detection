import os
import random
import csv
import logging
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/datasets", tags=["datasets"])

# Define path to Datasets directory
DATASETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "Datasets")

def get_all_datasets() -> Dict[str, Dict[str, str]]:
    """Dynamically scan the Datasets directory for all CSV files."""
    dataset_map = {}
    if not os.path.exists(DATASETS_DIR):
        return dataset_map
        
    for root, _, files in os.walk(DATASETS_DIR):
        for file in files:
            if file.endswith('.csv'):
                # Extract clean name for ID (e.g. from 'spam_ham_india.csv' to 'spam_ham_india')
                dataset_id = os.path.splitext(file)[0].lower()
                # Create a readable name path 
                rel_dir = os.path.relpath(root, DATASETS_DIR)
                if rel_dir == ".": rel_dir = "root"
                
                dataset_map[dataset_id] = {
                    "path": os.path.join(root, file),
                    "folder": rel_dir
                }
    return dataset_map

@router.get("/")
async def list_datasets():
    """Returns a list of all dynamically discovered datasets"""
    dataset_map = get_all_datasets()
    available = []
    for k, v in dataset_map.items():
        available.append({
            "id": k,
            "folder": v["folder"],
            "available": True,
            "path": v["path"]
        })
    return {"datasets": available}

@router.get("/{dataset_type}/sample")
async def get_dataset_sample(dataset_type: str = Path(..., description="The ID (filename without extension) of dataset to sample from")):
    """Returns a random row sample formatted as text from the dynamically discovered CSV."""
    
    dataset_map = get_all_datasets()
    
    if dataset_type not in dataset_map:
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_type}' not found. Available count: {len(dataset_map)}")
        
    config = dataset_map[dataset_type]
    file_path = config["path"]
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            headers = next(reader, None)
            
            if not headers:
                raise HTTPException(status_code=500, detail="Empty CSV file")
                
            rows = list(reader)
            if not rows:
                raise HTTPException(status_code=500, detail="No data rows in CSV file")
                
            random_row = random.choice(rows)
            text_content = ""
            
            # Smart text extraction logic: find the longest text field in the row
            # This makes it generic across any dataset shape
            valid_texts = [str(cell) for cell in random_row if len(str(cell).strip()) > 3]
            if valid_texts:
                # Get the cell with the most characters
                text_content = max(valid_texts, key=len)
            else:
                text_content = " | ".join(random_row)
            
            row_dict = dict(zip(headers, random_row))
            
            if len(text_content) > 1000:
                text_content = text_content[:1000] + "... [truncated]"

            result = {
                "dataset": dataset_type,
                "text": text_content,
                "metadata": row_dict
            }
            return result
            
    except Exception as e:
        logger.error(f"Error reading dataset {dataset_type} at {file_path}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
